#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This script must run as root." >&2
    exit 1
fi

if nft list table inet sic >/dev/null 2>&1; then
    nft delete table inet sic
    echo "Removed nftables table inet sic."
else
    echo "No inet sic table exists; nothing to remove."
fi

if [[ $# -eq 1 ]]; then
    peer_if=$1
    if [[ ! -d /sys/class/net/$peer_if ]]; then
        echo "Cannot restore MTU: interface does not exist: $peer_if" >&2
        exit 1
    fi
    ip link set dev "$peer_if" mtu 1500
    echo "Restored $peer_if MTU to 1500."
fi

echo "IP forwarding and offload settings are intentionally left unchanged."
