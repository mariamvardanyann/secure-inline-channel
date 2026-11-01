#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this script as root: sudo $0" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libnetfilter-queue-dev \
    nftables \
    iproute2 \
    ethtool \
    curl \
    tcpdump \
    python3 \
    shellcheck \
    zip

echo "Dependencies installed. Build with: make"
