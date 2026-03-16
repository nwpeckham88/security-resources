#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "Hiatus Botnet Basic Detection Script"

# IOC subset from Black Lotus Labs Hiatus feed.
HIATUS_IOC_IPS="104.250.48.192 46.8.113.227 207.246.80.240 45.63.70.57 155.138.213.169 66.135.22.245 107.189.11.105"
HIATUS_IOC_HASHES="774f2f3a801ddfe5d8a9ab1b90398ee28ee2be3d7ad0fa75eacbdf7ab51f6939 766e13d2a085c7c1b5e37fe0be92658932a13cfbcadf5b08977420fc6ac6d3e3 193481c4e2cbd14a29090f500f88455e1394140b9c5857937f86d2b854b54f60 98ec46ac0e3b0b49140f710d0437e03e1f89f9b6fc092be7a5a1fde7d59e312e"

section "Checking cron/cru for Hiatus-like persistence markers..."
CRON_OUTPUT=$(collect_cron_output)
if echo "$CRON_OUTPUT" | grep -Ei 'hiatus|tcpdump|upload|heartbeat|wget|curl.*sh|/tmp/' >/dev/null 2>&1; then
    warn "Suspicious cron/cru entries may indicate Hiatus-like persistence."
else
    ok "No obvious Hiatus-like cron persistence entries found."
fi
echo ""

section "Checking running processes for Hiatus-like behavior..."
if ps w 2>/dev/null | grep -Ei 'tcpdump|packet|proxy|/tmp/.{1,16}|hiatus' | grep -Ev 'grep|detect-hiatus' >/dev/null 2>&1; then
    warn "Potential Hiatus process pattern detected."
else
    ok "No obvious Hiatus process patterns detected."
fi
echo ""

section "Checking active connections for Hiatus IOC IPs..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "Hiatus" "$HIATUS_IOC_IPS" "$NET_OUTPUT"
    if [ "$?" -eq 0 ]; then
        ok "No active connections to listed Hiatus IOC IPs found."
    fi
fi
echo ""

section "Checking known suspicious staging paths..."
check_suspicious_file_paths "Hiatus" "/tmp/hiatus /var/run/hiatus /tmp/.h /tmp/.sockd /tmp/.proxy"
if [ "$?" -eq 0 ]; then
    ok "No known Hiatus suspicious file paths found."
fi
echo ""

section "Checking dropped-file hashes in common staging paths..."
init_hash_tool
if [ -z "$HASH_TOOL" ]; then
    note "No SHA256 utility available (sha256sum/openssl)."
else
    scan_hashes_in_dirs "Hiatus" "$HIATUS_IOC_HASHES" "/tmp /var/run /var/tmp /jffs /jffs/scripts"
    if [ "$?" -eq 0 ]; then
        ok "No listed Hiatus hashes found in scanned paths."
    fi
fi
echo ""

section "Checking Merlin startup hooks for suspicious payload execution..."
scan_startup_hooks_for_regex "Hiatus" 'tcpdump|wget|curl|/tmp/|/var/run/'
if [ "$?" -eq 0 ]; then
    ok "No suspicious startup hook indicators detected."
fi

print_footer
