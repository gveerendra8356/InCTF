# 🔍 Forensics Cheat Sheet & Tools

## Essential Commands

### Volatility 3 (Memory Analysis)
* Process List: `vol -f mem.raw windows.pslist`
* Command Line Arguments: `vol -f mem.raw windows.cmdline`
* Dump Process Memory: `vol -f mem.raw windows.dumpfiles --pid `

### Network Analysis (TShark / Scapy)
* Extract HTTP Requests: `tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri`
* Extract DNS Queries: `tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name`

### Steganography & File Carving
* Inspect Metadata: `exiftool image.png`
* Extract Embedded Files: `binwalk -e file.bin` or `foremost -i file.bin`
