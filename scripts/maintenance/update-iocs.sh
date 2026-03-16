#!/bin/sh

set -u

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
IOC_DIR="$ROOT_DIR/iocs"
TMP_DIR="${TMPDIR:-/tmp}/security-resources-iocs-$$"

mkdir -p "$TMP_DIR"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to update IOCs."
    exit 1
fi

fetch_file() {
    src_url="$1"
    out_file="$2"
    curl -fsSL "$src_url" -o "$out_file"
}

# Pull raw IOC text files as optional refresh artifacts.
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/KadNap_IOCs.txt" "$TMP_DIR/KadNap_IOCs.txt" || true
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/KVbotnet_IOCs.txt" "$TMP_DIR/KVbotnet_IOCs.txt" || true
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/ZuoRAT_IoCs.txt" "$TMP_DIR/ZuoRAT_IoCs.txt" || true
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/Hiatus_2_IOCs.txt" "$TMP_DIR/Hiatus_2_IOCs.txt" || true
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/Raptor_Train_IOCs.txt" "$TMP_DIR/Raptor_Train_IOCs.txt" || true
fetch_file "https://raw.githubusercontent.com/blacklotuslabs/IOCs/main/Chaos_IoCs.txt" "$TMP_DIR/Chaos_IoCs.txt" || true

mkdir -p "$IOC_DIR/raw"
cp -f "$TMP_DIR"/*.txt "$IOC_DIR/raw/" 2>/dev/null || true

echo "IOC raw files refreshed into: $IOC_DIR/raw"
echo "Manual curation into seed files under $IOC_DIR is still required."
