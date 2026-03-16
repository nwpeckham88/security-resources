#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "KVbotnet Basic Detection Script"

# IOC set from Black Lotus Labs KVbotnet feed (curated starter subset).
KVBOTNET_IOC_IPS="152.32.138.247 45.159.209.228 45.63.60.39 45.32.174.131 207.246.100.151 66.42.124.155 104.156.246.150 149.28.119.73 45.32.88.250 108.61.203.19 140.82.20.246 159.203.72.166"
KVBOTNET_IOC_HASHES="7043ffd9ce3fe48c9fb948ae958a2e9966d29afe380d6b61d5efb826b70334f5 690638c702170dba9e43b0096944c4e7540b827218afbfaebc902143cda4f2a7 48299c2c568ce5f0d4f801b4aee0a6109b68613d2948ce4948334bbd7adc49eb 0279435f8727cca99bee575d157187787174d39f6872c2067de23afc681fe586 c524e118b1e263fccac6e94365b3a0b148a53ea96df21c8377ccd8ec3d6a0874 2711f1341d2f150a0c3e2d596939805d66ba7c6403346513d1fc826324f63c87 5928f67db54220510f6863c0edc0343fdb68f7c7070496a3f49f99b3b545daf9"

KVBOTNET_IOC_FILE=$(ioc_file_path "kvbotnet")
KVBOTNET_IOC_IPS_FILE=$(ioc_values "$KVBOTNET_IOC_FILE" "IP")
KVBOTNET_IOC_HASHES_FILE=$(ioc_values "$KVBOTNET_IOC_FILE" "SHA256")
if [ -n "$KVBOTNET_IOC_IPS_FILE" ]; then
    KVBOTNET_IOC_IPS="$KVBOTNET_IOC_IPS_FILE"
fi
if [ -n "$KVBOTNET_IOC_HASHES_FILE" ]; then
    KVBOTNET_IOC_HASHES="$KVBOTNET_IOC_HASHES_FILE"
fi

section "Checking scheduled tasks for suspicious KVbotnet persistence markers..."
CRON_OUTPUT=$(crontab -l 2>/dev/null)
if has_cmd cru; then
    CRON_OUTPUT="$CRON_OUTPUT\n$(cru l 2>/dev/null)"
fi

if echo "$CRON_OUTPUT" | grep -Ei 'kv|cli_download|payload|wget|curl.*sh' >/dev/null 2>&1; then
    warn "Suspicious cron/cru entries may indicate KVbotnet persistence."
else
    ok "No obvious KVbotnet-like cron persistence entries found."
fi
echo ""

section "Checking running processes for known KVbotnet execution patterns..."
if ps w 2>/dev/null | grep -Ei 'kv|cli_download|nosedive|/tmp/.{1,16}' | grep -Ev 'grep|detect-kvbotnet' >/dev/null 2>&1; then
    warn "Potential KVbotnet process pattern detected."
else
    ok "No obvious KVbotnet process patterns detected."
fi
echo ""

section "Checking active connections for KVbotnet IOC IPs..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "KVbotnet" "$KVBOTNET_IOC_IPS" "$NET_OUTPUT"
    if [ "$?" -eq 0 ]; then
        ok "No active connections to listed KVbotnet IOC IPs found."
    fi
fi
echo ""

section "Checking dropped-file hashes in common router staging paths..."
init_hash_tool
if [ -z "$HASH_TOOL" ]; then
    note "No SHA256 utility available (sha256sum/openssl)."
else
    scan_hashes_in_dirs "KVbotnet" "$KVBOTNET_IOC_HASHES" "/tmp /var/run /var/tmp /jffs /jffs/scripts"
    if [ "$?" -eq 0 ]; then
        ok "No listed KVbotnet hashes found in scanned paths."
    fi
fi
echo ""

section "Checking common Merlin startup hook paths..."
for hook in /jffs/scripts/services-start /jffs/scripts/wan-start /jffs/scripts/firewall-start /jffs/scripts/nat-start /jffs/scripts/post-mount; do
    if [ -f "$hook" ] && grep -Ei 'kv|cli_download|wget|curl|/tmp/' "$hook" >/dev/null 2>&1; then
        warn "Suspicious startup hook content: $hook"
    fi
done

if [ "$WARN_COUNT" -eq 0 ]; then
    ok "No suspicious Merlin startup hook indicators detected."
fi

print_footer
