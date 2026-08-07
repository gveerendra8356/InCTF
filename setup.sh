#!/usr/bin/env bash
# Arch Linux CTF Environment Bootstrapper

set -e

echo "[*] Arch Linux Environment Detected."

# 1. Check pacman availability
if command -v pacman &> /dev/null; then
    echo "[*] Updating pacman database & installing core system dependencies..."
    sudo pacman -Sy --needed --noconfirm \
        python \
        python-pip \
        binwalk \
        steghide \
        exiftool \
        pngcheck \
        hashcat \
        john \
        openssl
fi

# 2. Handle Python PEP 668 (externally-managed-environment) on Arch
echo "[*] Initializing isolated Python virtual environment (.venv)..."
python3 -m venv .venv --system-site-packages
source .venv/bin/activate

# 3. Install Python dependencies inside venv
if [ -f "requirements.txt" ]; then
    echo "[*] Installing Python packages inside virtual environment..."
    pip install --upgrade pip
    pip install -r requirements.txt
fi

echo "[+] Arch Linux setup complete!"
echo "[+] To run your tools, use: source .venv/bin/activate"
