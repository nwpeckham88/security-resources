#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib-router-detect.sh
. "$SCRIPT_DIR/lib-router-detect.sh"

print_header "ASUSWRT/Merlin Baseline Security Audit"

section "Reviewing cron/cru persistence entries..."
CRON_OUTPUT=$(collect_cron_output)
if echo "$CRON_OUTPUT" | grep -Ei 'wget|curl|nc |telnet|chmod \+x|/tmp/|/var/run/' >/dev/null 2>&1; then
    warn "Cron/cru contains potentially risky execution patterns."
    printf "%s\n" "$CRON_OUTPUT" | sed 's/^/        /'
else
    ok "No high-risk cron/cru execution patterns found."
fi
echo ""

section "Reviewing Merlin startup hooks..."
scan_startup_hooks_for_regex "Baseline" 'wget|curl|nc |telnet|/tmp/|/var/run/|iptables -t nat|ip rule add|ip route add'
if [ "$?" -eq 0 ]; then
    ok "No high-risk startup-hook patterns detected."
fi
echo ""

section "Reviewing DNS configuration..."
if [ -f /etc/resolv.conf ]; then
    DNS_SERVERS=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
    if [ -n "$DNS_SERVERS" ]; then
        note "Active resolvers: $DNS_SERVERS"
    else
        note "No nameserver entries found in /etc/resolv.conf"
    fi
fi

if [ -f /etc/dnsmasq.conf ] && grep -Ei '^server=' /etc/dnsmasq.conf >/dev/null 2>&1; then
    note "Custom dnsmasq servers detected in /etc/dnsmasq.conf"
    grep -Ei '^server=' /etc/dnsmasq.conf | sed 's/^/        /'
fi

if [ -d /jffs/configs ] && grep -R 'server=' /jffs/configs >/dev/null 2>&1; then
    note "Custom dnsmasq server overrides detected under /jffs/configs"
fi
echo ""

section "Reviewing active network connections..."
NET_OUTPUT=$(collect_net_output)
if [ -z "$NET_OUTPUT" ]; then
    note "Could not collect connection data (no netstat/ss available)."
else
    if echo "$NET_OUTPUT" | grep -E ':(23|2323|48101|37215|4444|5555|6667|7777|8080|8888)\b' >/dev/null 2>&1; then
        warn "Connections on commonly abused C2/scanning ports were observed."
        echo "$NET_OUTPUT" | grep -E ':(23|2323|48101|37215|4444|5555|6667|7777|8080|8888)\b' | sed 's/^/        /'
    else
        ok "No obvious connections on commonly abused C2/scanning ports."
    fi
fi
echo ""

section "Reviewing firewall and routing modifications..."
if has_cmd iptables; then
    IPT_NAT=$(iptables -t nat -S 2>/dev/null)
    if echo "$IPT_NAT" | grep -Ei 'REDIRECT|DNAT|SNAT' >/dev/null 2>&1; then
        note "NAT table has redirect/translation rules (review expectedness)."
    else
        ok "No NAT redirect/translation rules reported."
    fi
else
    note "iptables not available on this device build."
fi

if has_cmd ip; then
    if ip rule show 2>/dev/null | grep -v '^0:' >/dev/null 2>&1; then
        note "Custom policy routing rules detected."
    else
        ok "No custom policy routing rules detected."
    fi
else
    note "ip utility not available on this device build."
fi
echo ""

section "Reviewing volatile executable drops..."
VOLATILE_FINDINGS=$(find /tmp /var/run /var/tmp -maxdepth 2 -type f -perm -u+x 2>/dev/null)
if [ -n "$VOLATILE_FINDINGS" ]; then
    warn "Executable files found in volatile directories."
    echo "$VOLATILE_FINDINGS" | sed 's/^/        /'
else
    ok "No user-executable files found in volatile directories (depth <= 2)."
fi

print_footer
