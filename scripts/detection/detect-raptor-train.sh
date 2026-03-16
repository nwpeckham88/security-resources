#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "Raptor Train Basic Detection Script"

RAPTOR_IOC_IPS="45.13.199.140 45.13.199.152 92.223.30.232 92.223.30.241 155.138.151.225"
RAPTOR_IOC_DOMAINS="zdacasdc.w8510.com zdacxzd.w8510.com qacassdfawemp.w8510.com kuyw.b2047.com xaqw.k3121.com"

RAPTOR_IOC_FILE=$(ioc_file_path "raptor-train")
RAPTOR_IOC_IPS_FILE=$(ioc_values "$RAPTOR_IOC_FILE" "IP")
RAPTOR_IOC_DOMAINS_FILE=$(ioc_values "$RAPTOR_IOC_FILE" "DOMAIN")
[ -n "$RAPTOR_IOC_IPS_FILE" ] && RAPTOR_IOC_IPS="$RAPTOR_IOC_IPS_FILE"
[ -n "$RAPTOR_IOC_DOMAINS_FILE" ] && RAPTOR_IOC_DOMAINS="$RAPTOR_IOC_DOMAINS_FILE"

section "Checking process list for shell-dropper behaviors..."
if ps w 2>/dev/null | grep -Ei 'wget http|curl http|rm -rf \$0|/var/tmp|/tmp/.{1,16}' | grep -Ev 'grep|detect-raptor' >/dev/null 2>&1; then
    warn "Potential Raptor Train dropper-like process behavior detected."
else
    ok "No obvious Raptor Train dropper process behavior detected."
fi

echo ""
section "Checking active connections for Raptor Train IOC IPs..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    scan_ioc_ips_in_connections "RaptorTrain" "$RAPTOR_IOC_IPS" "$NET_OUTPUT"
    if [ "$?" -eq 0 ]; then
        ok "No active connections to listed Raptor Train IOC IPs found."
    fi
fi

echo ""
section "Checking startup/config files for IOC domains..."
scan_ioc_domains_in_files "RaptorTrain" "$RAPTOR_IOC_DOMAINS" "/etc/dnsmasq.conf /jffs/scripts/services-start /jffs/scripts/wan-start /jffs/scripts/firewall-start /jffs/scripts/nat-start /jffs/scripts/post-mount"
if [ "$?" -eq 0 ]; then
    ok "No Raptor Train IOC domains found in startup/config files."
fi

echo ""
section "Checking startup hooks for suspicious dropper regex..."
scan_startup_hooks_for_regex "RaptorTrain" 'wget http|curl http|rm -rf \$0|/var/tmp|/tmp/'
if [ "$?" -eq 0 ]; then
    ok "No suspicious startup hook patterns detected."
fi

print_footer
