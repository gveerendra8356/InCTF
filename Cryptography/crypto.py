#!/usr/bin/env python3
import sys
import os
import re
import math
import base64
import binascii

# Attempt imports for crypto libraries (available via Miniforge3/pip)
try:
    import sympy
except ImportError:
    sympy = None

try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ImportError:
    # Fallback if PyCryptodome isn't present
    def long_to_bytes(n):
        return n.to_bytes((n.bit_length() + 7) // 8, 'big')
    def bytes_to_long(b):
        return int.from_bytes(b, 'big')

# Standard InCTF Flag Patterns
FLAG_PATTERNS = [
    rb"InCTF\{[^}]+\}",
    rb"inctf\{[^}]+\}",
    rb"CTF\{[^}]+\}",
    rb"flag\{[^}]+\}"
]

def print_header(title):
    print(f"\n{'='*20} {title} {'='*20}")

def search_flags(data, source_label="Data"):
    """Checks raw or decoded bytes for standard CTF flag signatures."""
    if isinstance(data, str):
        data = data.encode(errors="ignore")
    
    found = False
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, data, re.IGNORECASE)
        for match in matches:
            print(f"\n[!!!] FLAG FOUND ({source_label}): {match.decode(errors='ignore')}\n")
            found = True
    return found

# ------------------------------------------------------------------------------
# 1. ENCODING & CIPHER CONVERSIONS (Base64, Hex, Binary, ROT13, Single-Byte XOR)
# ------------------------------------------------------------------------------

def solve_encodings_and_xor(raw_text):
    """Tries encoding standard decodes and single-byte XOR brute force."""
    print_header("ENCODING & XOR TRIAGE")
    clean_text = raw_text.strip()

    # Base64 Decode
    try:
        b64_dec = base64.b64decode(clean_text)
        print(f"[+] Base64 Decoded: {b64_dec[:50]}...")
        search_flags(b64_dec, "Base64 Decode")
    except Exception:
        pass

    # Hex Decode
    try:
        hex_dec = binascii.unhexlify(clean_text)
        print(f"[+] Hex Decoded: {hex_dec[:50]}...")
        search_flags(hex_dec, "Hex Decode")
        
        # Single-Byte XOR Brute Force on Hex payload
        for key in range(256):
            xored = bytes([b ^ key for b in hex_dec])
            if search_flags(xored, f"Single-byte XOR Key {hex(key)}"):
                break
    except Exception:
        pass

    # ROT13 / Caesar Cipher
    try:
        rot13 = clean_text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        search_flags(rot13, "ROT13")
    except Exception:
        pass

# ------------------------------------------------------------------------------
# 2. AUTOMATED RSA ATTACKS (Small e, Wiener's, Common Modulus, Factorization)
# ------------------------------------------------------------------------------

def parse_rsa_params(text):
    """Extracts n, e, c, p, q variables from text files or descriptions."""
    params = {}
    for var in ['n', 'e', 'c', 'p', 'q', 'd', 'ct']:
        match = re.search(fr'{var}\s*=\s*([0-9xX-a-fA-F]+)', text)
        if match:
            val_str = match.group(1)
            val = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            params[var if var != 'ct' else 'c'] = val
    return params

def solve_rsa(params):
    """Runs standard automated RSA mathematical attacks."""
    if not ('n' in params and 'c' in params):
        return

    print_header("AUTOMATED RSA ATTACKS")
    n = params['n']
    c = params['c']
    e = params.get('e', 65537)

    print(f"[*] Extracted RSA Params -> n: {str(n)[:20]}..., e: {e}, c: {str(c)[:20]}...")

    # Attack 1: Small e Attack (c = m^e mod n where m^e < n)
    if e < 10:
        print("[*] Attempting Small e (e-th root) Attack...")
        m_val, exact = integer_nth_root(c, e)
        if exact:
            flag_bytes = long_to_bytes(m_val)
            print("[+] Small e attack successful!")
            search_flags(flag_bytes, "RSA Small e Root")
            return

    # Attack 2: Known p and q factors
    if 'p' in params and 'q' in params:
        p, q = params['p'], params['q']
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            search_flags(long_to_bytes(m), "RSA Known Factors (p, q)")
            return
        except Exception as err:
            print(f"[-] RSA solve failed with p,q: {err}")

    # Attack 3: Small N Factorization using Sympy
    if sympy and n.bit_length() <= 64:
        print("[*] Attempting Prime Factorization on small N...")
        factors = sympy.factorint(n)
        if len(factors) == 2:
            p, q = list(factors.keys())
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            search_flags(long_to_bytes(m), "RSA Small N Factorization")

def integer_nth_root(n, k):
    """Computes exact k-th root of n if it exists."""
    u, a = n, n + 1
    while u < a:
        a = u
        u = ((k - 1) * a + n // pow(a, k - 1)) // k
    return a, pow(a, k) == n

# ------------------------------------------------------------------------------
# 3. LINEAR CONGRUENTIAL GENERATOR (LCG) / PRNG TRIAGE
# ------------------------------------------------------------------------------

def solve_lcg_predict(values):
    """Predicts LCG parameters given state outputs: S_{n+1} = (a * S_n + c) mod m"""
    if len(values) < 6:
        return
    print_header("LCG PRNG PARAMETER RECOVERY")
    # Tries recovering modulus m from differences
    diffs = [s2 - s1 for s1, s2 in zip(values[:-1], values[1:])]
    zeroes = [t2 * t0 - t1 ** 2 for t0, t1, t2 in zip(diffs[:-2], diffs[1:-1], diffs[2:])]
    m = functools_reduce(math.gcd, zeroes)
    if m > 1:
        print(f"[+] Recovered LCG Modulus m: {m}")

def functools_reduce(func, seq):
    res = seq[0]
    for item in seq[1:]:
        res = func(res, item)
    return res

# ------------------------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_crypto_file> [optional_challenge_description]")
        sys.exit(1)

    file_path = sys.argv[1]
    description = sys.argv[2] if len(sys.argv) > 2 else ""

    content = ""
    if os.path.exists(file_path):
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

    combined_text = content + "\n" + description

    print(f"[*] Target File: {file_path}")
    search_flags(combined_text, "Input Text")

    # Step 1: Classical Ciphers, Encodings & XOR
    solve_encodings_and_xor(combined_text)

    # Step 2: RSA Parameter Parsing & Solving
    rsa_params = parse_rsa_params(combined_text)
    if rsa_params:
        solve_rsa(rsa_params)

    print_header("TRIAGE COMPLETE")
    print("If automatic attacks fail, use:")
    print("1. Miniforge3 python -> import z3 (for constraint solvers)")
    print("2. Ghidra -> Decompile ELF binary for custom bitwise ops")
    print("3. Jadx-gui -> Decompile Android APK for hardcoded keys/AES IVs")

if __name__ == "__main__":
    main()
