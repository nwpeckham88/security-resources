#!/bin/sh

# Shared helpers for ASUSWRT/Merlin detection scripts.

WARN_COUNT=0

print_header() {
    title="$1"
    echo "=========================================================="
    printf "  %s\n" "$title"
    echo "  (For Asuswrt/Merlin OS - Read-Only Diagnostic Check)"
    echo "=========================================================="
    echo ""
}

section() {
    printf "[+] %s\n" "$1"
}

warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    printf "    [!] WARNING: %s\n" "$1"
}

ok() {
    printf "    [-] %s\n" "$1"
}

note() {
    printf "    [*] %s\n" "$1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

collect_net_output() {
    if has_cmd netstat; then
        netstat -an 2>/dev/null
        return
    fi

    if has_cmd ss; then
        ss -antup 2>/dev/null
    fi
}

init_hash_tool() {
    HASH_TOOL=""

    if has_cmd sha256sum; then
        HASH_TOOL="sha256sum"
        return
    fi

    if has_cmd openssl; then
        HASH_TOOL="openssl"
    fi
}

file_sha256() {
    file="$1"

    if [ "$HASH_TOOL" = "sha256sum" ]; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
        return
    fi

    if [ "$HASH_TOOL" = "openssl" ]; then
        openssl dgst -sha256 "$file" 2>/dev/null | awk '{print $NF}'
    fi
}

scan_ioc_ips_in_connections() {
    family="$1"
    ioc_ips="$2"
    net_output="$3"

    found=0
    for ip in $ioc_ips; do
        if echo "$net_output" | grep -F "$ip" >/dev/null 2>&1; then
            warn "$family IOC network match: $ip"
            found=1
        fi
    done

    return "$found"
}

scan_hashes_in_dirs() {
    family="$1"
    ioc_hashes="$2"
    scan_dirs="$3"

    found=0
    for dir in $scan_dirs; do
        if [ ! -d "$dir" ]; then
            continue
        fi

        for file in "$dir"/* "$dir"/.*; do
            if [ ! -f "$file" ]; then
                continue
            fi

            file_hash=$(file_sha256 "$file")
            if [ -n "$file_hash" ] && echo "$ioc_hashes" | grep -F "$file_hash" >/dev/null 2>&1; then
                warn "$family hash match: $file"
                printf "        SHA256: %s\n" "$file_hash"
                found=1
            fi
        done
    done

    return "$found"
}

print_footer() {
    echo ""
    echo "=========================================================="
    echo "Diagnostic complete."
    if [ "$WARN_COUNT" -gt 0 ]; then
        echo "Warnings: $WARN_COUNT"
        echo "If warnings were triggered, investigate immediately."
    else
        echo "No warnings were triggered by this check set."
    fi
    echo "=========================================================="
}
