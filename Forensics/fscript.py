#!/usr/bin/env python3
"""
Forensics Module: Magic Byte Carving, Metadata Sweeps, LSB Stego & Network PCAP Parsing
"""

import os
import re
import subprocess
from PIL import Image
import exifread
from scapy.all import rdpcap, Raw

FILE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": ("PNG Image", ".png", b"\x49\x45\x4e\x44\xae\x42\x60\x82"),
    b"\xff\xd8\xff": ("JPEG Image", ".jpg", b"\xff\xd9"),
    b"PK\x03\x04": ("ZIP Archive", ".zip", b"PK\x05\x06"),
    b"%PDF": ("PDF Document", ".pdf", b"%%EOF"),
}

FLAG_REGEX = re.compile(rb"[A-Za-z0-9_]{2,10}\{[^{}\s]+\}", re.IGNORECASE)

def print_flag_matches(data: bytes, source: str):
    matches = FLAG_REGEX.findall(data)
    for m in set(matches):
        print(f"  [!!!] FLAG FOUND [{source}]: {m.decode('utf-8', errors='ignore')}")

def run_forensics_pipeline(filepath: str):
    print("\n==========================================")
    print("      RUNNING FORENSICS ANALYSIS          ")
    print("==========================================")

    if not os.path.exists(filepath):
        print(f"[-] Target file not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        content = f.read()

    print_flag_matches(content, "Raw Byte Scan")

    # 1. Carving File Magic Bytes
    print("\n[+] Layer 1: Magic Byte Carving")
    for sig, (name, ext, footer) in FILE_SIGNATURES.items():
        offsets = [m.start() for m in re.finditer(re.escape(sig), content)]
        if offsets:
            print(f"  [!] Header Found: {name} at offset(s): {offsets}")
            for start in offsets:
                if footer:
                    end = content.find(footer, start)
                    if end != -1:
                        carved = content[start:end + len(footer)]
                        out_name = f"carved_{start}{ext}"
                        with open(out_name, "wb") as out:
                            out.write(carved)
                        print(f"    [->] Carved {name} saved to {out_name}")
                        print_flag_matches(carved, out_name)

    # 2. Image Steganography Analysis
    ext = os.path.splitext(filepath)[1].lower()
    if ext in [".png", ".jpg", ".jpeg"]:
        print("\n[+] Layer 2: Steganography & EXIF Analysis")
        try:
            with open(filepath, "rb") as f:
                tags = exifread.process_file(f)
                for tag, val in tags.items():
                    print_flag_matches(str(val).encode(), f"EXIF {tag}")
        except Exception: pass

        if ext == ".png":
            subprocess.run(["zsteg", "-a", filepath], stderr=subprocess.DEVNULL)
        elif ext in [".jpg", ".jpeg"]:
            subprocess.run(["steghide", "extract", "-sf", filepath, "-p", ""], stderr=subprocess.DEVNULL)

    # 3. PCAP Analysis
    elif ext in [".pcap", ".pcapng"]:
        print("\n[+] Layer 3: Network Packet Stream Reassembly")
        try:
            packets = rdpcap(filepath)
            reassembled = bytearray()
            for pkt in packets:
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    reassembled.extend(payload)
                    print_flag_matches(payload, "Packet Raw Payload")
            print_flag_matches(bytes(reassembled), "Reassembled PCAP Stream")
        except Exception as e:
            print(f"  [-] PCAP Analysis Error: {e}")

    # 4. Binwalk Extraction
    print("\n[+] Layer 4: Deep Binwalk Carving")
    subprocess.run(["binwalk", "--extract", "--matryoshka", filepath])
