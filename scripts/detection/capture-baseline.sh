#!/bin/sh

set -u

OUT_DIR="${1:-baseline}"
TS=$(date +%Y%m%d-%H%M%S)
DEST="$OUT_DIR/$TS"

mkdir -p "$DEST"

crontab -l >"$DEST/crontab.txt" 2>/dev/null || true
cru l >"$DEST/cru.txt" 2>/dev/null || true
ps w >"$DEST/ps.txt" 2>/dev/null || true
netstat -an >"$DEST/netstat.txt" 2>/dev/null || ss -antup >"$DEST/netstat.txt" 2>/dev/null || true
iptables -S >"$DEST/iptables-filter.txt" 2>/dev/null || true
iptables -t nat -S >"$DEST/iptables-nat.txt" 2>/dev/null || true
ip rule show >"$DEST/ip-rule.txt" 2>/dev/null || true
ip route show table all >"$DEST/ip-route.txt" 2>/dev/null || true
cp -f /etc/resolv.conf "$DEST/resolv.conf" 2>/dev/null || true
cp -f /etc/dnsmasq.conf "$DEST/dnsmasq.conf" 2>/dev/null || true

find /jffs/scripts -type f -maxdepth 2 -exec sha256sum {} \; >"$DEST/jffs-scripts.sha256" 2>/dev/null || true

echo "Baseline saved to: $DEST"
