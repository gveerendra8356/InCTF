#!/usr/bin/env bash
set -e

echo "[*] Updating apt package index..."
sudo apt-get update -y

echo "[*] Installing core system dependencies & CTF tools..."
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    binwalk \
    steghide \
    exiftool \
    tshark \
    foremost \
    pngcheck \
    zsteg \
    hashcat \
    john \
    openssl

echo "[*] Creating Python virtual environment (.venv)..."
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Environment setup complete! Activate with: source .venv/bin/activate"
