#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
project_name=$(basename -- "$project_dir")
output=${1:-"$project_dir/../Secure_Inline_Channel_C_Submission.zip"}
staging=$(mktemp -d)

cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT

cp -a -- "$project_dir" "$staging/$project_name"
rm -rf -- "${staging:?}/${project_name:?}/bin" \
    "${staging:?}/${project_name:?}/build"
find "$staging/$project_name" -type f \
    \( -name '*.o' -o -name '*.gcda' -o -name '*.gcno' -o -name '*.zip' \) \
    -delete

mkdir -p -- "$(dirname -- "$output")"
rm -f -- "$output"
(
    cd "$staging"
    zip -q -r "$output" "$project_name"
)
echo "$output"
