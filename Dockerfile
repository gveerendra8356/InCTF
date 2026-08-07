FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    binwalk \
    steghide \
    exiftool \
    tshark \
    foremost \
    pngcheck \
    zsteg \
    hashcat \
    john \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "main.py"]
