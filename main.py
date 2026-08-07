#!/usr/bin/env python3
"""
CTF Crypto & Forensics Automated Challenge Solver
"""

import sys
import argparse
from modules.crypto import run_crypto_pipeline
from modules.forensics import run_forensics_pipeline

def main():
    parser = argparse.ArgumentParser(description="CTF Crypto & Forensics Auto Solver")
    parser.add_argument("target", help="Ciphertext string, hex string, or file path to analyze")
    parser.add_argument("--type", choices=["crypto", "forensics", "auto"], default="auto", 
                        help="Type of analysis to run (default: auto-detect)")

    args = parser.parse_args()

    target = args.target
    mode = args.type

    if mode == "crypto":
        run_crypto_pipeline(target)
    elif mode == "forensics":
        run_forensics_pipeline(target)
    else:
        # Auto-detect mode
        if os.path.exists(target):
            print(f"[*] Target '{target}' recognized as a File. Launching Forensics Pipeline...")
            run_forensics_pipeline(target)
        else:
            print(f"[*] Target recognized as Text/Ciphertext. Launching Crypto Pipeline...")
            run_crypto_pipeline(target)

if __name__ == "__main__":
    import os
    main()
