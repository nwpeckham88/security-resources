#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "KadNap Botnet Basic Detection Script"

KADNAP_IOC_IPS="85.158.111.100 89.46.38.74 154.7.253.12 212.104.141.88 91.193.19.226 79.141.161.152 91.193.19.51 79.141.163.155 23.227.203.221 45.135.180.38 45.135.180.177"
KADNAP_IOC_HASHES="0b3dbb951de7a216dd5032d783ba7d0a5ecda2bf872643c3a4ddd1667fb38ffe ebf9de6b67e94b2bd2b0dcda1941e04fef1a1dad830404813e468ab8744b7ed8"

section "Checking scheduled tasks (cron/cru) for KadNap persistence patterns..."
CRON_OUTPUT=$(crontab -l 2>/dev/null)
if has_cmd cru; then
    CRON_OUTPUT="$CRON_OUTPUT\n$(cru l 2>/dev/null)"
fi

if echo "$CRON_OUTPUT" | grep -E '^55 ' >/dev/null 2>&1; then
    warn "Found a cron job executing at the 55th minute (known KadNap IOC pattern)."
else
    ok "No suspicious cron jobs found at the 55-minute mark."
fi
echo ""

section "Checking running processes for known KadNap patterns..."
if ps w 2>/dev/null | grep -E '\.asusrouter|kad' | grep -Ev 'grep|detect-kadnap' >/dev/null 2>&1; then
    warn "Found suspicious running processes matching 'kad' or '.asusrouter'."
else
    ok "No suspicious running process patterns detected."
fi
echo ""

section "Checking known dropped file paths..."
found_files=0
for target in /tmp/kad /tmp/.asusrouter /tmp/aic.sh /var/run/kad /var/run/.asusrouter; do
    if [ -f "$target" ]; then
        warn "Found suspicious file: $target"
        found_files=1
    fi
done
if [ "$found_files" -eq 0 ]; then
    ok "No known KadNap files found in standard temp directories."
fi
echo ""

section "Checking active connections for KadNap IOC IPs..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "KadNap" "$KADNAP_IOC_IPS" "$NET_OUTPUT"
    if [ "$?" -eq 0 ]; then
        ok "No active connections to known KadNap IOC IPs were found."
    fi
fi
echo ""

section "Checking dropped-file hashes against known KadNap samples..."
init_hash_tool
if [ -z "$HASH_TOOL" ]; then
    note "No SHA256 utility available (sha256sum/openssl)."
else
    scan_hashes_in_dirs "KadNap" "$KADNAP_IOC_HASHES" "/tmp /var/run"
    if [ "$?" -eq 0 ]; then
        ok "No known KadNap sample hashes found in /tmp or /var/run."
    fi
fi

echo ""
print_footer
echo "Please consider performing a factory reset and updating to the latest firmware."
echo ""