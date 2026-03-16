#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "Mirai/Chaos Basic Detection Script"

MIRAI_IOC_IPS="198.98.55.123"
MIRAI_IOC_DOMAINS="linuxddos.net quanquandd.top"
MIRAI_IOC_HASHES="e0e3d23222d71bbebae6afd37dcc436f9f5c8e56dd6ece8c8d63c162826dd99c d315b83e772dfddbd2783f016c38f021225745eb43c06bbdfd92364f68fa4c56"
MIRAI_PORTS="23 2323 48101"

MIRAI_IOC_FILE=$(ioc_file_path "mirai")
MIRAI_IOC_IPS_FILE=$(ioc_values "$MIRAI_IOC_FILE" "IP")
MIRAI_IOC_DOMAINS_FILE=$(ioc_values "$MIRAI_IOC_FILE" "DOMAIN")
MIRAI_IOC_HASHES_FILE=$(ioc_values "$MIRAI_IOC_FILE" "SHA256")
MIRAI_PORTS_FILE=$(ioc_values "$MIRAI_IOC_FILE" "PORT")
[ -n "$MIRAI_IOC_IPS_FILE" ] && MIRAI_IOC_IPS="$MIRAI_IOC_IPS_FILE"
[ -n "$MIRAI_IOC_DOMAINS_FILE" ] && MIRAI_IOC_DOMAINS="$MIRAI_IOC_DOMAINS_FILE"
[ -n "$MIRAI_IOC_HASHES_FILE" ] && MIRAI_IOC_HASHES="$MIRAI_IOC_HASHES_FILE"
[ -n "$MIRAI_PORTS_FILE" ] && MIRAI_PORTS="$MIRAI_PORTS_FILE"

section "Checking for common Mirai process patterns..."
if ps w 2>/dev/null | grep -Ei 'mirai|anime|dvrhelper|/tmp/.{1,16}' | grep -Ev 'grep|detect-mirai' >/dev/null 2>&1; then
    warn "Potential Mirai-like process pattern detected."
else
    ok "No obvious Mirai process patterns detected."
fi

echo ""
section "Checking active connections for Mirai IOC IPs and ports..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "Mirai" "$MIRAI_IOC_IPS" "$NET_OUTPUT"
    found_ports=0
    for port in $MIRAI_PORTS; do
        if echo "$NET_OUTPUT" | grep -E ":$port\b" >/dev/null 2>&1; then
            warn "Connection observed on Mirai-associated port: $port"
            found_ports=1
        fi
    done
    if [ "$?" -eq 0 ] && [ "$found_ports" -eq 0 ]; then
        ok "No Mirai IOC IP matches or associated port activity found."
    fi
fi

echo ""
section "Checking startup/config files for IOC domains..."
scan_ioc_domains_in_files "Mirai" "$MIRAI_IOC_DOMAINS" "/etc/dnsmasq.conf /jffs/scripts/services-start /jffs/scripts/wan-start /jffs/scripts/firewall-start /jffs/scripts/nat-start /jffs/scripts/post-mount"
if [ "$?" -eq 0 ]; then
    ok "No Mirai IOC domains found in startup/config files."
fi

echo ""
section "Checking dropped-file hashes in common staging paths..."
init_hash_tool
if [ -z "$HASH_TOOL" ]; then
    note "No SHA256 utility available (sha256sum/openssl)."
else
    scan_hashes_in_dirs "Mirai" "$MIRAI_IOC_HASHES" "/tmp /var/run /var/tmp /jffs /jffs/scripts"
    if [ "$?" -eq 0 ]; then
        ok "No listed Mirai/Chaos hashes found in scanned paths."
    fi
fi

print_footer
