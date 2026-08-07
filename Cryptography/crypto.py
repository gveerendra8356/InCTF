#!/usr/bin/env python3
import sys
import os
import re
import math
import base64
import binascii
from functools import reduce

# Attempt imports for crypto libraries (Miniforge3)
try:
    import sympy
except ImportError:
    sympy = None

try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long, GCD
    from Crypto.Cipher import AES
except ImportError:
    # Fallback if PyCryptodome isn't present
    def long_to_bytes(n):
        return n.to_bytes((n.bit_length() + 7) // 8, 'big')
    def bytes_to_long(b):
        return int.from_bytes(b, 'big')
    def GCD(a, b):
        return math.gcd(a, b)

# Flag Patterns for InCTF formats
FLAG_PATTERNS = [
    rb"InCTF\{[^}]+\}",
    rb"inctf\{[^}]+\}",
    rb"inctfj\{[^}]+\}",
    rb"CTF\{[^}]+\}",
    rb"flag\{[^}]+\}"
]

def print_header(title):
    print(f"\n{'='*20} {title} {'='*20}")

def search_flags(data, source_label="Data"):
    """Scans binary or text data for standard CTF flag patterns."""
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
# 1. ENCODING, REPEATED-KEY XOR & AES-CTR REUSE
# ------------------------------------------------------------------------------

def solve_encodings_and_xor(raw_text):
    """Tries encoding decodes, single-byte XOR, and known-plaintext XOR."""
    print_header("ENCODING & XOR TRIAGE")
    clean_text = raw_text.strip()

    # Hex Decode
    try:
        hex_dec = binascii.unhexlify(re.sub(r'[^0-9a-fA-F]', '', clean_text))
        search_flags(hex_dec, "Hex Decode")
        
        # Single-Byte XOR Brute Force
        for key in range(256):
            xored = bytes([b ^ key for b in hex_dec])
            if search_flags(xored, f"Single-byte XOR Key {hex(key)}"):
                break

        # Known-Plaintext XOR Attack using 'InCTF{' prefix
        known_prefix = b"InCTF{"
        if len(hex_dec) >= len(known_prefix):
            key_part = bytes([hex_dec[i] ^ known_prefix[i] for i in range(len(known_prefix))])
            print(f"[*] Deduced Key Prefix (using 'InCTF{{'): {key_part}")
            # Repeats key_part over hex_dec length
            repeating_key = (key_part * (len(hex_dec) // len(key_part) + 1))[:len(hex_dec)]
            xored = bytes([a ^ b for a, b in zip(hex_dec, repeating_key)])
            search_flags(xored, "Known Plaintext Repeating XOR")
    except Exception:
        pass

# ------------------------------------------------------------------------------
# 2. ADVANCED AUTOMATED RSA ATTACKS
# ------------------------------------------------------------------------------

def integer_nth_root(n, k):
    """Computes exact k-th root of n if it exists."""
    u, a = n, n + 1
    while u < a:
        a = u
        u = ((k - 1) * a + n // pow(a, k - 1)) // k
    return a, pow(a, k) == n

def fermat_factorization(n, max_steps=1000000):
    """Fermat's Factorization for RSA when p and q are close (InCTF Common Pattern)."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    for _ in range(max_steps):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            return p, q
        a += 1
        b2 = a * a - n
    return None, None

def wieners_attack(e, n):
    """Wiener's Attack for small private exponent d < (1/3) * n^(1/4)."""
    def continued_fractions(e, n):
        cf = []
        while n != 0:
            q = e // n
            cf.append(q)
            e, n = n, e - q * n
        return cf

    def convergents(cf):
        convs = []
        p0, q0 = 0, 1
        p1, q1 = 1, 0
        for a in cf:
            p2 = a * p1 + p0
            q2 = a * q1 + q0
            convs.append((p2, q2))
            p0, q0 = p1, q1
            p1, q1 = p2, q2
        return convs

    cf = continued_fractions(e, n)
    convs = convergents(cf)

    for k, d in convs:
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discriminant = s * s - 4 * n
            if discriminant >= 0:
                root = math.isqrt(discriminant)
                if root * root == discriminant and (s + root) % 2 == 0:
                    return d
    return None

def parse_rsa_params(text):
    """Extracts RSA parameters (n, e, c, p, q, d) from input files or descriptions."""
    params = {}
    for var in ['n', 'e', 'c', 'p', 'q', 'd', 'ct']:
        match = re.search(fr'{var}\s*=\s*([0-9xX-a-fA-F]+)', text)
        if match:
            val_str = match.group(1)
            val = int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            params[var if var != 'ct' else 'c'] = val
    return params

def solve_rsa(params):
    """Executes automated RSA attack strategies."""
    if not ('n' in params and 'c' in params):
        return

    print_header("AUTOMATED RSA ATTACKS")
    n = params['n']
    c = params['c']
    e = params.get('e', 65537)

    print(f"[*] RSA Parameters Loaded -> n bit-length: {n.bit_length()}, e: {e}")

    # Attack 1: Small e / Hastad's Root Attack (c = m^e mod n where m^e < n)
    if e < 10:
        print("[*] Attempting Small e (e-th root) Attack...")
        m_val, exact = integer_nth_root(c, e)
        if exact:
            search_flags(long_to_bytes(m_val), "RSA Small e Root")
            return

    # Attack 2: Known p and q factors
    if 'p' in params and 'q' in params:
        p, q = params['p'], params['q']
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        search_flags(long_to_bytes(m), "RSA Known Factors")
        return

    # Attack 3: Fermat Factorization (Close Primes p and q)
    print("[*] Checking Fermat's Factorization (p ≈ q)...")
    p, q = fermat_factorization(n)
    if p and q:
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        search_flags(long_to_bytes(m), "RSA Fermat Factorization")
        return

    # Attack 4: Wiener's Attack (Small d)
    print("[*] Checking Wiener's Attack (Small d)...")
    d = wieners_attack(e, n)
    if d:
        m = pow(c, d, n)
        search_flags(long_to_bytes(m), "RSA Wiener's Attack")
        return

    # Attack 5: Factorization via Sympy for Small N
    if sympy and n.bit_length() <= 64:
        print("[*] Factoring small modulus using Sympy...")
        factors = sympy.factorint(n)
        if len(factors) == 2:
            p, q = list(factors.keys())
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            search_flags(long_to_bytes(m), "RSA Sympy Factorization")

# ------------------------------------------------------------------------------
# 3. LCG PRNG PARAMETER RECOVERY (S_{n+1} = (a * S_n + c) mod m)
# ------------------------------------------------------------------------------

def solve_lcg_from_outputs(states):
    """Recovers m, a, c from LCG state outputs and predicts flag stream."""
    if len(states) < 6:
        return
    print_header("LCG PARAMETER RECOVERY")
    try:
        diffs = [s2 - s1 for s1, s2 in zip(states[:-1], states[1:])]
        zeroes = [t2 * t0 - t1 ** 2 for t0, t1, t2 in zip(diffs[:-2], diffs[1:-1], diffs[2:])]
        m = reduce(math.gcd, zeroes)
        if m > 1:
            a = ((states[2] - states[1]) * pow(states[1] - states[0], -1, m)) % m
            c = (states[1] - a * states[0]) % m
            print(f"[+] Recovered LCG Params -> Modulus m: {m}, Multiplier a: {a}, Increment c: {c}")
            
            # Reconstruct keystream / next states
            next_state = (a * states[-1] + c) % m
            search_flags(long_to_bytes(next_state), "LCG Next State Output")
    except Exception as err:
        print(f"[*] LCG parameter recovery skipped: {err}")

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
    search_flags(combined_text, "Input Description/Text")

    # Step 1: Classical Ciphers & Encodings
    solve_encodings_and_xor(combined_text)

    # Step 2: Automated RSA Attacks
    rsa_params = parse_rsa_params(combined_text)
    if rsa_params:
        solve_rsa(rsa_params)

    # Step 3: Check for LCG outputs in text
    numbers = [int(x) for x in re.findall(r'\b\d{5,}\b', combined_text)]
    if len(numbers) >= 6:
        solve_lcg_from_outputs(numbers)

    print_header("AUTOMATED TRIAGE COMPLETE")

if __name__ == "__main__":
    main()
