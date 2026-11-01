#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage: sudo setup_device.sh ROLE HOST_IF PEER_IF PROTECTED_PORT [ENC_QUEUE] [DEC_QUEUE]

ROLE is device1 or device2. HOST_IF faces the local PC; PEER_IF faces the
other security device. Default queues are 100 (encrypt) and 101 (decrypt).
USAGE
}

if [[ ${EUID} -ne 0 ]]; then
    echo "This script must run as root." >&2
    exit 1
fi
if [[ $# -lt 4 || $# -gt 6 ]]; then
    usage
    exit 2
fi

role=$1
host_if=$2
peer_if=$3
protected_port=$4
encrypt_queue=${5:-100}
decrypt_queue=${6:-101}

if [[ $role != device1 && $role != device2 ]]; then
    usage
    exit 2
fi
for value in "$protected_port" "$encrypt_queue" "$decrypt_queue"; do
    if [[ ! $value =~ ^[0-9]+$ ]] || ((value < 0 || value > 65535)); then
        echo "Invalid numeric value: $value" >&2
        exit 2
    fi
done
if ((protected_port == 0 || encrypt_queue == decrypt_queue)); then
    echo "Port must be nonzero and queue numbers must differ." >&2
    exit 2
fi
for interface in "$host_if" "$peer_if"; do
    if [[ ! -d /sys/class/net/$interface ]]; then
        echo "Interface does not exist: $interface" >&2
        exit 1
    fi
done
for command in nft ip sysctl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing command: $command" >&2
        exit 1
    fi
done
if nft list table inet sic >/dev/null 2>&1; then
    echo "nftables table 'inet sic' already exists; run cleanup_device.sh first." >&2
    exit 1
fi

sysctl -q -w net.ipv4.ip_forward=1

# The encrypted packet is exactly 16 bytes longer because of the GCM tag.
# A 1520-byte inter-device MTU carries a full 1500-byte original packet.
ip link set dev "$peer_if" mtu 1520

# Packet aggregation can hide the one-IP-packet-at-a-time view from NFQUEUE.
if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$host_if" gro off gso off tso off lro off 2>/dev/null || true
    ethtool -K "$peer_if" gro off gso off tso off lro off 2>/dev/null || true
fi

nft add table inet sic
nft 'add chain inet sic forward { type filter hook forward priority -150; policy accept; }'

# Drop selected-path IPv4 fragments instead of letting non-initial fragments
# bypass the TCP-port match. The prototype intentionally supports whole packets.
nft add rule inet sic forward iifname "$host_if" oifname "$peer_if" \
    ip protocol tcp ip frag-off \& 0x3fff != 0 counter drop \
    comment "\"sic reject host-to-peer fragments\""
nft add rule inet sic forward iifname "$peer_if" oifname "$host_if" \
    ip protocol tcp ip frag-off \& 0x3fff != 0 counter drop \
    comment "\"sic reject peer-to-host fragments\""

if [[ $role == device1 ]]; then
    nft add rule inet sic forward iifname "$host_if" oifname "$peer_if" \
        ip protocol tcp tcp dport "$protected_port" counter \
        queue num "$encrypt_queue" \
        comment "\"sic device1 encrypt request\""
    nft add rule inet sic forward iifname "$peer_if" oifname "$host_if" \
        ip protocol tcp tcp sport "$protected_port" counter \
        queue num "$decrypt_queue" \
        comment "\"sic device1 decrypt response\""
else
    nft add rule inet sic forward iifname "$peer_if" oifname "$host_if" \
        ip protocol tcp tcp dport "$protected_port" counter \
        queue num "$decrypt_queue" \
        comment "\"sic device2 decrypt request\""
    nft add rule inet sic forward iifname "$host_if" oifname "$peer_if" \
        ip protocol tcp tcp sport "$protected_port" counter \
        queue num "$encrypt_queue" \
        comment "\"sic device2 encrypt response\""
fi

echo "Configured $role: $host_if <-> $peer_if, protected TCP port $protected_port"
echo "Rules are fail-closed: protected payload packets wait/drop unless sicd owns the queues."
nft list table inet sic
