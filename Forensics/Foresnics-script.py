#!/usr/bin/env python3
import sys
import os
import re
import subprocess
import zlib
import zipfile
import binascii
import base64
from PIL import Image

# Expanded Flag patterns for InCTF formats
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
            
    # Try decoding base64 candidates automatically
    b64_candidates = re.findall(rb'[A-Za-z0-9+/]{16,}={0,2}', data)
    for cand in b64_candidates:
        try:
            decoded = base64.b64decode(cand)
            for pattern in FLAG_PATTERNS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    print(f"\n[!!!] FLAG FOUND IN BASE64 ({source_label}): {decoded.decode(errors='ignore')}\n")
                    found = True
        except Exception:
            continue

    return found

def repair_corrupted_headers(file_path):
    """Detects and automatically fixes common corrupted magic bytes (InCTF Corrupt style)."""
    print_header("HEADER INTEGRITY & REPAIR CHECK")
    with open(file_path, "rb") as f:
        data = f.read()

    header = data[:8]
    hex_header = binascii.hexlify(header).decode()
    print(f"[*] Original Header: {hex_header}")

    # Check for known corrupted ZIP header (e.g., 70 4b 05 06 -> 50 4b 03 04)
    if data.startswith(b"\x70\x4b") or data.startswith(b"\x50\x4b\x05\x06"):
        print("[!] Detected corrupted ZIP archive header! Repairing...")
        repaired_data = b"\x50\x4b\x03\x04" + data[4:]
        repaired_path = file_path + "_repaired.zip"
        with open(repaired_path, "wb") as f:
            f.write(repaired_data)
        print(f"[+] Written repaired file to: {repaired_path}")
        analyze_archive(repaired_path)
        return repaired_path

    # Check for corrupted PNG header (\x89PNG missing or modified)
    if b"PNG\r\n\x1a\n" in data[:16] and not data.startswith(b"\x89PNG"):
        print("[!] Detected corrupted PNG magic byte! Repairing...")
        repaired_data = b"\x89PNG\r\n\x1a\n" + data[8:]
        repaired_path = file_path + "_repaired.png"
        with open(repaired_path, "wb") as f:
            f.write(repaired_data)
        print(f"[+] Written repaired PNG file to: {repaired_path}")
        analyze_image_stego(repaired_path)
        return repaired_path

    return file_path

def analyze_image_stego(file_path):
    """Performs LSB extraction and metadata analysis on images."""
    if not file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        return

    print_header("IMAGE METADATA & LSB STEGANOGRAPHY")
    
    # 1. Check EXIF/Metadata via Exiftool if installed
    try:
        res = subprocess.run(["exiftool", file_path], capture_output=True, text=True)
        if res.returncode == 0:
            print("[*] EXIF Data Summary:")
            search_flags(res.stdout, "EXIF Metadata")
    except FileNotFoundError:
        print("[*] exiftool not installed, skipping advanced EXIF dump.")

    # 2. LSB Steganography Extraction (Red/Green/Blue/Alpha bit planes)
    try:
        img = Image.open(file_path)
        pixels = img.load()
        width, height = img.size

        extracted_bits = []
        for y in range(min(height, 200)):  # Scan first 200 rows for quick triage
            for x in range(min(width, 200)):
                pixel = pixels[x, y]
                if isinstance(pixel, tuple):
                    extracted_bits.append(str(pixel[0] & 1))  # R-LSB

        bit_string = "".join(extracted_bits)
        bytes_list = [int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8)]
        decoded_bytes = bytes(bytes_list)
        
        search_flags(decoded_bytes, "LSB Stego (Red Channel)")
    except Exception as e:
        print(f"[*] Image LSB analysis failed: {e}")

def analyze_network_pcap(file_path):
    """Carves credentials, HTTP traffic, and embedded files from PCAP files."""
    if not file_path.lower().endswith(('.pcap', '.pcapng', '.cap')):
        return

    print_header("NETWORK PCAP TRIAGE")
    try:
        # Extract HTTP Requests / User Agents / Flags using tshark
        cmd = ["tshark", "-r", file_path, "-Y", "http or dns", "-T", "fields", "-e", "http.file_data", "-e", "dns.qry.name"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and res.stdout:
            print("[*] Extracted HTTP/DNS Traffic Data...")
            search_flags(res.stdout, "PCAP Tshark Extraction")
            
        # Export HTTP objects automatically
        output_dir = "./pcap_extracted_files"
        os.makedirs(output_dir, exist_ok=True)
        subprocess.run(["tshark", "-r", file_path, "--export-objects", f"http,{output_dir}"], capture_output=True)
        print(f"[+] Carved network objects saved to: {output_dir}")
        
        for root, _, files in os.walk(output_dir):
            for file in files:
                filepath = os.path.join(root, file)
                with open(filepath, "rb") as f:
                    search_flags(f.read(), f"Extracted Object: {file}")
    except FileNotFoundError:
        print("[*] Tshark CLI not found. Use Zui for PCAP analysis.")

def extract_strings_and_zlib(file_path):
    """Extracts strings, Zlib blocks, and compressed streams."""
    print_header("STRINGS & EMBEDDED STREAM CARVING")
    with open(file_path, "rb") as f:
        content = f.read()

    search_flags(content, "Raw File")

    # Extract printable strings containing relevant CTF keywords
    ascii_strings = re.findall(rb"[\x20-\x7e]{6,}", content)
    for s in ascii_strings:
        if any(k in s.lower() for k in [b"flag", b"inctf", b"pass", b"key", b"secret", b"user"]):
            print(f"[+] Keyword String: {s.decode(errors='ignore')}")

    # Search for Zlib decompressed payloads
    for i in range(len(content) - 2):
        if content[i:i+2] in [b'\x78\x01', b'\x78\x9c', b'\x78\xda']:
            try:
                decompressed = zlib.decompress(content[i:])
                search_flags(decompressed, f"Zlib Stream @ {hex(i)}")
            except zlib.error:
                continue

def analyze_archive(file_path):
    """Inspects ZIP/APK structures and extracts content."""
    if zipfile.is_zipfile(file_path):
        print_header("ZIP ARCHIVE / APK INSPECTION")
        with zipfile.ZipFile(file_path, 'r') as z:
            for filename in z.namelist():
                print(f"  - {filename}")
                search_flags(filename.encode(), "Zip Filename")
                try:
                    data = z.read(filename)
                    search_flags(data, f"Inside {filename}")
                except Exception:
                    pass

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_forensics_file> [optional_challenge_description]")
        sys.exit(1)

    file_path = sys.argv[1]
    description = sys.argv[2] if len(sys.argv) > 2 else ""

    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        sys.exit(1)

    print(f"[*] Target File: {file_path}")
    if description:
        print(f"[*] Challenge Description: {description}")
        search_flags(description.encode(), "Description Text")

    # Step 1: Repair Corrupted File Headers
    working_file = repair_corrupted_headers(file_path)

    # Step 2: Extract Embedded Data / Zlib / Strings
    extract_strings_and_zlib(working_file)

    # Step 3: Archive & Compressed File Parsing
    analyze_archive(working_file)

    # Step 4: Specialized File Handlers (Image & PCAP)
    analyze_image_stego(working_file)
    analyze_network_pcap(working_file)

    print_header("TRIAGE COMPLETE")

if __name__ == "__main__":
    main()
