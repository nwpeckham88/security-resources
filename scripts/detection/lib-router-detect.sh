#!/bin/sh

# Shared helpers for ASUSWRT/Merlin detection scripts.

WARN_COUNT=0
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
FINDINGS_LOG="${FINDINGS_LOG:-}"
SIMPLE_MODE="${SIMPLE_MODE:-0}"

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
    if [ "$SIMPLE_MODE" = "1" ]; then
        printf "    [!] Problem found: %s\n" "$1"
    else
        printf "    [!] WARNING: %s\n" "$1"
    fi
    if [ -n "$FINDINGS_LOG" ]; then
        printf "high|%s\n" "$1" >>"$FINDINGS_LOG"
    fi
}

ok() {
    if [ "$SIMPLE_MODE" = "1" ]; then
        printf "    [-] OK: %s\n" "$1"
    else
        printf "    [-] %s\n" "$1"
    fi
}

note() {
    printf "    [*] %s\n" "$1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

ioc_values() {
    ioc_file="$1"
    ioc_type="$2"

    if [ ! -f "$ioc_file" ]; then
        return
    fi

    grep -E "^${ioc_type}:" "$ioc_file" 2>/dev/null | cut -d: -f2- | tr '\n' ' '
}

ioc_file_path() {
    family="$1"
    printf "%s/iocs/%s.txt" "$REPO_ROOT" "$family"
}

print_security_reminder() {
    echo ""
    echo "Security reminder: disable SSH on the router when you are done if continuous access is not needed."
}

collect_cron_output() {
    output=$(crontab -l 2>/dev/null)
    if has_cmd cru; then
        output="$output\n$(cru l 2>/dev/null)"
    fi
    printf "%s\n" "$output"
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

scan_ioc_domains_in_files() {
    family="$1"
    ioc_domains="$2"
    target_files="$3"

    found=0
    for target in $target_files; do
        if [ ! -f "$target" ]; then
            continue
        fi

        for domain in $ioc_domains; do
            if grep -F "$domain" "$target" >/dev/null 2>&1; then
                warn "$family IOC domain found in $target: $domain"
                found=1
            fi
        done
    done

    return "$found"
}

scan_startup_hooks_for_regex() {
    label="$1"
    regex="$2"

    found=0
    for hook in /jffs/scripts/services-start /jffs/scripts/wan-start /jffs/scripts/firewall-start /jffs/scripts/nat-start /jffs/scripts/post-mount; do
        if [ -f "$hook" ] && grep -Ei "$regex" "$hook" >/dev/null 2>&1; then
            warn "$label suspicious startup hook content: $hook"
            found=1
        fi
    done

    return "$found"
}

check_suspicious_file_paths() {
    label="$1"
    paths="$2"

    found=0
    for path in $paths; do
        if [ -f "$path" ]; then
            warn "$label suspicious file path exists: $path"
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
