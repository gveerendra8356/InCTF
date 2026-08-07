#!/usr/bin/env python3
"""
Crypto Module: Multi-Decoders, RSA Attack Engines, Custom XOR & Z3 Solvers
"""

import math
import re
import base64
import subprocess
import shutil
import z3
import sympy
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, inverse

FLAG_PATTERNS = [
    r"[A-Za-z0-9_]{2,10}\{[^{}\s]+\}",
    r"CTF\{[^{}\s]+\}",
    r"FLAG\{[^{}\s]+\}"
]

def score_text(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    score = printable / len(data)
    try:
        text = data.decode('utf-8', errors='ignore')
        for pat in FLAG_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                score += 5.0
    except Exception:
        pass
    return score

def extract_flags(data: bytes) -> list:
    candidates = []
    try:
        text = data.decode('utf-8', errors='ignore')
        for pat in FLAG_PATTERNS:
            matches = re.findall(pat, text, re.IGNORECASE)
            candidates.extend(matches)
    except Exception:
        pass
    return list(set(candidates))

def run_crypto_pipeline(target_input: str):
    print("\n==========================================")
    print("      CRACKING CRYPTO CHALLENGE           ")
    print("==========================================")

    # 1. Multi-Base Decoding & Sweeps
    print("\n[+] Layer 1: Multi-Base Encodings & Single-Byte XOR Sweeps")
    results = []

    try:
        results.append(("Base64", base64.b64decode(target_input.strip())))
    except Exception: pass

    try:
        results.append(("Base32", base64.b32decode(target_input.strip())))
    except Exception: pass

    try:
        results.append(("Hex", base64.b16decode(target_input.strip().upper())))
    except Exception: pass

    # ROT/Caesar
    for shift in range(1, 26):
        shifted = []
        for char in target_input:
            if 'a' <= char <= 'z':
                shifted.append(chr((ord(char) - 97 + shift) % 26 + 97))
            elif 'A' <= char <= 'Z':
                shifted.append(chr((ord(char) - 65 + shift) % 26 + 65))
            else:
                shifted.append(char)
        results.append((f"ROT-{shift}", "".join(shifted).encode()))

    # XOR Sweep
    try:
        raw_bytes = bytes.fromhex(target_input.strip())
    except Exception:
        raw_bytes = target_input.encode()

    for k in range(256):
        results.append((f"XOR Key 0x{k:02x}", bytes([b ^ k for b in raw_bytes])))

    for tag, res in results:
        sc = score_text(res)
        flags = extract_flags(res)
        if flags or sc > 3.5:
            print(f"  [!] Match Found [{tag}]: {flags if flags else res[:80]}")

    # 2. Z3 Constraint Solving Engine Demonstration
    print("\n[+] Layer 2: Z3 SMT Constraint Prover Check")
    s = z3.Solver()
    x = z3.BitVec('x', 32)
    s.add((x ^ 0xDEADBEEF) == 0xCAFEBABE)
    if s.check() == z3.sat:
        m = s.model()
        print(f"  [!] Z3 Prover Functional: Solved Key = {hex(m[x].as_long())}")
