#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "ZuoRAT Basic Detection Script"

# IOC subset from Black Lotus Labs ZuoRAT feed.
ZUORAT_IOC_IPS="141.98.212.62 103.140.187.131 202.178.11.78 101.99.91.10 110.42.185.232"
ZUORAT_IOC_DOMAINS="memthree.com"
ZUORAT_IOC_HASHES="3230ab2a8cd28ef9f463fabfb879df4ea00447605b18488d64e6fc12850371fc 2f4359f91a92fa56d4aa0940ecb928042e20787b660c95e853e944ba92b02f17"

section "Checking cron/cru for suspicious router persistence patterns..."
CRON_OUTPUT=$(crontab -l 2>/dev/null)
if has_cmd cru; then
    CRON_OUTPUT="$CRON_OUTPUT\n$(cru l 2>/dev/null)"
fi

if echo "$CRON_OUTPUT" | grep -Ei 'zuorat|dns\.php|ssid\.php|wget|curl.*sh|/tmp/' >/dev/null 2>&1; then
    warn "Suspicious cron/cru entries may indicate ZuoRAT-like persistence."
else
    ok "No obvious ZuoRAT-like cron persistence entries found."
fi
echo ""

section "Checking processes for ZuoRAT-like execution clues..."
if ps w 2>/dev/null | grep -Ei 'zuorat|dns\.php|ssid\.php|/tmp/.{1,16}' | grep -Ev 'grep|detect-zuorat' >/dev/null 2>&1; then
    warn "Potential ZuoRAT process pattern detected."
else
    ok "No obvious ZuoRAT process patterns detected."
fi
echo ""

section "Checking active connections for ZuoRAT IOC IPs..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "ZuoRAT" "$ZUORAT_IOC_IPS" "$NET_OUTPUT"
    if [ "$?" -eq 0 ]; then
        ok "No active connections to listed ZuoRAT IOC IPs found."
    fi
fi
echo ""

section "Checking startup hooks and configs for ZuoRAT IOC domains..."
for target in /jffs/scripts/services-start /jffs/scripts/wan-start /jffs/scripts/firewall-start /jffs/scripts/nat-start /jffs/scripts/post-mount /etc/dnsmasq.conf; do
    if [ ! -f "$target" ]; then
        continue
    fi

    for domain in $ZUORAT_IOC_DOMAINS; do
        if grep -F "$domain" "$target" >/dev/null 2>&1; then
            warn "IOC domain reference found in $target: $domain"
        fi
    done
done

if [ "$WARN_COUNT" -eq 0 ]; then
    ok "No ZuoRAT IOC domains found in scanned startup/config files."
fi

echo ""
section "Checking dropped-file hashes in common staging paths..."
init_hash_tool
if [ -z "$HASH_TOOL" ]; then
    note "No SHA256 utility available (sha256sum/openssl)."
else
    scan_hashes_in_dirs "ZuoRAT" "$ZUORAT_IOC_HASHES" "/tmp /var/run /var/tmp /jffs /jffs/scripts"
    if [ "$?" -eq 0 ]; then
        ok "No listed ZuoRAT hashes found in scanned paths."
    fi
fi

print_footer
