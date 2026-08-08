# 🚩 InCTF — Cryptography & Forensics Write-ups & Tools

Welcome to my repository for **InCTF** challenge write-ups, analysis notes, and custom automated scripts, focusing on **Cryptography** and **Digital Forensics**. 

This repository serves as a knowledge base and portfolio documenting various attack vectors, analysis methodologies, and solution scripts encountered during CTF competitions.

---

## 🛠️ Category Breakdown

### 🔐 Cryptography (`/cryptography`)
Focuses on weak cryptographic implementations, mathematical attacks, and algorithm breaking.

* **Classical Ciphers:** Substitution, Vigenère, Caesar, Transposition variants.
* **Asymmetric Encryption (RSA & ECC):**
  * Low Exponent Attacks ($e = 3$) & Common Modulus Attacks.
  * Wiener's Attack & Hastad's Broadcast Attack.
  * Factorization via Wiener, Pollard's $p-1$, and ECM.
  * Discrete Logarithm Problem (DLP) over finite fields and elliptic curves.
* **Symmetric Encryption:** AES Mode misconfigurations (ECB oracle attacks, CBC bit-flipping, IV reuse).
* **PRNGs & Hashes:** Hash length extension attacks and linear congruential generator (LCG) predictability.

---

### 🔍 Digital Forensics (`/forensics`)
Focuses on artifact recovery, network traffic dissection, memory analysis, and hidden data extraction.

* **Memory Forensics:** Volatility 2 & 3 scripts, process tree analysis, dump extraction, malware artifact identification.
* **Network Analysis:** Wireshark filtering, Scapy packet dissection, PCAP stream carving, custom protocol analysis.
* **Steganography:** Audio spectrogram analysis, LSB image extraction, metadata inspection (`exiftool`), binwalk/foremost file carving.
* **Disk & OS Artifacts:** Registry hive analysis, event log evaluation, shellbags, and timeline reconstruction.

---
https://github.com/Pavithra-1977
https://GitHub.com/vishnu0523
