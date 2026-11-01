#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"

make test
make sanitize
make smoke

if [[ ${EUID} -eq 0 ]] && command -v nft >/dev/null 2>&1; then
    echo "Running privileged namespace integration test..."
    ./tests/test_integration.sh
else
    echo "Skipping privileged integration test (requires root, nft, and bin/sicd)."
fi
