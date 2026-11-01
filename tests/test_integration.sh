#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
namespaces=(sic-pc1 sic-d1 sic-d2 sic-pc2)
work_dir=$(mktemp -d)
background_pids=()

cleanup() {
    local pid namespace
    for pid in "${background_pids[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${background_pids[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    for namespace in "${namespaces[@]}"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

if [[ ${EUID} -ne 0 ]]; then
    echo "Integration test requires root." >&2
    exit 1
fi
for command in ip nft curl python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Integration test requires: $command" >&2
        exit 1
    fi
done
if [[ ! -x $project_dir/bin/sicd ]]; then
    echo "Build bin/sicd first with: make" >&2
    exit 1
fi
for namespace in "${namespaces[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
        echo "Network namespace already exists: $namespace" >&2
        exit 1
    fi
done

for namespace in "${namespaces[@]}"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
done

ip link add sic-v-pc1 type veth peer name sic-v-d1h
ip link add sic-v-d1p type veth peer name sic-v-d2p
ip link add sic-v-d2h type veth peer name sic-v-pc2

ip link set sic-v-pc1 netns sic-pc1
ip link set sic-v-d1h netns sic-d1
ip link set sic-v-d1p netns sic-d1
ip link set sic-v-d2p netns sic-d2
ip link set sic-v-d2h netns sic-d2
ip link set sic-v-pc2 netns sic-pc2

ip -n sic-pc1 link set sic-v-pc1 name eth0
ip -n sic-d1 link set sic-v-d1h name host0
ip -n sic-d1 link set sic-v-d1p name peer0
ip -n sic-d2 link set sic-v-d2p name peer0
ip -n sic-d2 link set sic-v-d2h name host0
ip -n sic-pc2 link set sic-v-pc2 name eth0

ip -n sic-pc1 address add 10.0.1.2/24 dev eth0
ip -n sic-d1 address add 10.0.1.1/24 dev host0
ip -n sic-d1 address add 10.0.12.1/30 dev peer0
ip -n sic-d2 address add 10.0.12.2/30 dev peer0
ip -n sic-d2 address add 10.0.2.1/24 dev host0
ip -n sic-pc2 address add 10.0.2.2/24 dev eth0

for specification in \
    "sic-pc1 eth0" "sic-d1 host0" "sic-d1 peer0" \
    "sic-d2 peer0" "sic-d2 host0" "sic-pc2 eth0"; do
    read -r namespace interface <<<"$specification"
    ip -n "$namespace" link set "$interface" up
done
ip -n sic-pc1 route add default via 10.0.1.1
ip -n sic-pc2 route add default via 10.0.2.1
ip -n sic-d1 route add 10.0.2.0/24 via 10.0.12.2
ip -n sic-d2 route add 10.0.1.0/24 via 10.0.12.1

ip netns exec sic-d1 "$project_dir/scripts/setup_device.sh" \
    device1 host0 peer0 8080 100 101 >"$work_dir/setup-d1.log"
ip netns exec sic-d2 "$project_dir/scripts/setup_device.sh" \
    device2 host0 peer0 8080 100 101 >"$work_dir/setup-d2.log"

cat >"$work_dir/device1.conf" <<'CONFIG'
role=device1
peer_address=10.0.12.2
control_port=47000
encrypt_queue=100
decrypt_queue=101
replay_window=128
counter_lookahead=128
connect_timeout_seconds=10
log_level=debug
psk_hex=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CONFIG
cat >"$work_dir/device2.conf" <<'CONFIG'
role=device2
listen_address=10.0.12.2
control_port=47000
encrypt_queue=100
decrypt_queue=101
replay_window=128
counter_lookahead=128
connect_timeout_seconds=10
log_level=debug
psk_hex=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CONFIG
printf '%s\n' 'integration-secret-7f31d2' >"$work_dir/index.html"

ip netns exec sic-pc2 python3 -m http.server 8080 \
    --bind 10.0.2.2 --directory "$work_dir" \
    >"$work_dir/http.log" 2>&1 &
background_pids+=("$!")
ip netns exec sic-d2 "$project_dir/bin/sicd" \
    --config "$work_dir/device2.conf" >"$work_dir/d2.log" 2>&1 &
background_pids+=("$!")
ip netns exec sic-d1 "$project_dir/bin/sicd" \
    --config "$work_dir/device1.conf" >"$work_dir/d1.log" 2>&1 &
background_pids+=("$!")

ready=0
for _ in $(seq 1 100); do
    if grep -q "packet processing active" "$work_dir/d1.log" 2>/dev/null &&
       grep -q "packet processing active" "$work_dir/d2.log" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if ((ready == 0)); then
    echo "Daemons did not become ready." >&2
    sed -n '1,120p' "$work_dir/d1.log" >&2
    sed -n '1,120p' "$work_dir/d2.log" >&2
    exit 1
fi

capture_pid=
if command -v tcpdump >/dev/null 2>&1; then
    ip netns exec sic-d1 timeout 5 tcpdump -i peer0 -s0 -A \
        'tcp port 8080' >"$work_dir/peer.capture" 2>&1 &
    capture_pid=$!
    background_pids+=("$capture_pid")
    sleep 0.2
fi

response=$(ip netns exec sic-pc1 curl --fail --silent --show-error \
    --max-time 5 http://10.0.2.2:8080/)
if [[ $response != "integration-secret-7f31d2" ]]; then
    echo "Unexpected HTTP response: $response" >&2
    exit 1
fi

sleep 0.3
if [[ -n $capture_pid ]]; then
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    if grep -aFq "integration-secret-7f31d2" "$work_dir/peer.capture"; then
        echo "Plaintext was visible on the inter-device link." >&2
        exit 1
    fi
fi
if ! grep -q "encrypted packet" "$work_dir/d1.log" ||
   ! grep -q "decrypted packet" "$work_dir/d2.log" ||
   ! grep -q "encrypted packet" "$work_dir/d2.log" ||
   ! grep -q "decrypted packet" "$work_dir/d1.log"; then
    echo "Expected bidirectional transformations were not logged." >&2
    exit 1
fi

echo "[PASS] namespace integration: HTTP succeeded through encrypted inline path"
echo "[PASS] both directions encrypted/decrypted protected TCP payloads"
if [[ -n $capture_pid ]]; then
    echo "[PASS] plaintext marker absent from inter-device packet capture"
fi
