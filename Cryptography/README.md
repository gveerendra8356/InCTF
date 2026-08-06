# 🔐 Cryptography Cheat Sheet & Tools

## Quick Formula Reference
* **RSA Modulus:** $N = p \times q$
* **Euler's Totient:** $\phi(N) = (p - 1)(q - 1)$
* **Private Key Exponent:** $d \equiv e^{-1} \pmod{\phi(N)}$
* **Decryption:** $m \equiv c^d \pmod N$

## Common Tools & Commands
* `RsaCtfTool`: `python3 RsaCtfTool.py -n  -e  --uncipher `
* `CyberChef`: Useful for quick encoding/decoding (Base64, Hex, XOR).
* `SageMath`: Essential for Discrete Log (DLP) & Elliptic Curves (ECC).
