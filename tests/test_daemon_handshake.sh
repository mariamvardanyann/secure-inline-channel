#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
device1_pid=
device2_pid=

cleanup() {
    if [[ -n $device1_pid ]]; then
        kill "$device1_pid" 2>/dev/null || true
        wait "$device1_pid" 2>/dev/null || true
    fi
    if [[ -n $device2_pid ]]; then
        kill "$device2_pid" 2>/dev/null || true
        wait "$device2_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

cd "$project_dir"
if [[ ! -x bin/sicd ]]; then
    echo "Build bin/sicd first with: make" >&2
    exit 1
fi

./bin/sicd --config tests/fixtures/device2-loopback.conf \
    >"$work_dir/device2.log" 2>&1 &
device2_pid=$!
sleep 0.2
./bin/sicd --config tests/fixtures/device1-loopback.conf \
    >"$work_dir/device1.log" 2>&1 &
device1_pid=$!

ready=0
for _ in $(seq 1 100); do
    if grep -q "secure session established" "$work_dir/device1.log" 2>/dev/null &&
       grep -q "secure session established" "$work_dir/device2.log" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$device1_pid" 2>/dev/null &&
       ! kill -0 "$device2_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ((ready == 0)); then
    echo "Daemon handshake smoke test failed." >&2
    sed -n '1,120p' "$work_dir/device1.log" >&2
    sed -n '1,120p' "$work_dir/device2.log" >&2
    exit 1
fi

device1_session=$(grep -m1 "secure session established" \
    "$work_dir/device1.log" | sed 's/.*id=//')
device2_session=$(grep -m1 "secure session established" \
    "$work_dir/device2.log" | sed 's/.*id=//')
if [[ -z $device1_session || $device1_session != "$device2_session" ]]; then
    echo "The daemons derived different session identifiers." >&2
    exit 1
fi

echo "[PASS] two sicd processes completed FFDHE2048/HKDF key confirmation"
echo "[PASS] both peers derived session id $device1_session"
