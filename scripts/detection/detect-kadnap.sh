#!/bin/sh

echo "=========================================================="
echo "          KadNap Botnet Basic Detection Script            "
echo "   (For Asuswrt/Merlin OS - Read-Only Diagnostic Check)   "
echo "=========================================================="
echo ""

# 1. Check for malicious cron jobs
echo "[+] Checking scheduled tasks (cron jobs) for the 55-minute mark..."
# Asus routers often use the 'cru' utility or standard crontabs
CRON_OUTPUT=$(crontab -l 2>/dev/null)
if command -v cru >/dev/null 2>&1; then
    CRON_OUTPUT="$CRON_OUTPUT\n$(cru l 2>/dev/null)"
fi

if echo "$CRON_OUTPUT" | grep -E '^55 ' >/dev/null; then
    echo "    [!] WARNING: Found a cron job executing at the 55th minute. This is a known KadNap IoC."
else
    echo "    [-] No suspicious cron jobs found at the 55-minute mark."
fi
echo ""

# 2. Check for suspicious processes
echo "[+] Checking running processes for known KadNap binaries..."
if ps | grep -E '\.asusrouter|kad' | grep -v grep >/dev/null; then
    echo "    [!] WARNING: Found suspicious running processes matching 'kad' or '.asusrouter'."
else
    echo "    [-] No suspicious running processes detected."
fi
echo ""

# 3. Check for malicious files in volatile storage
echo "[+] Checking volatile directories (/tmp, /var) for dropped files..."
found_files=0
for target in "/tmp/kad" "/tmp/.asusrouter" "/tmp/aic.sh" "/var/run/kad" "/var/run/.asusrouter"; do
    if [ -f "$target" ]; then
        echo "    [!] WARNING: Found suspicious file: $target"
        found_files=1
    fi
done

if [ "$found_files" -eq 0 ]; then
    echo "    [-] No known KadNap files found in standard temp directories."
fi
echo ""

# 4. Check active and historical IOC IPs in current network connections
echo "[+] Checking active network connections for KadNap IOC IPs..."
IOC_IPS="85.158.111.100 89.46.38.74 154.7.253.12 212.104.141.88 91.193.19.226 79.141.161.152 91.193.19.51 79.141.163.155 23.227.203.221 45.135.180.38 45.135.180.177"

NET_OUTPUT=""
if command -v netstat >/dev/null 2>&1; then
    NET_OUTPUT="$(netstat -an 2>/dev/null)"
elif command -v ss >/dev/null 2>&1; then
    NET_OUTPUT="$(ss -antup 2>/dev/null)"
fi

found_ioc_ips=0
if [ -n "$NET_OUTPUT" ]; then
    for ip in $IOC_IPS; do
        if echo "$NET_OUTPUT" | grep -F "$ip" >/dev/null; then
            echo "    [!] WARNING: Found network connection involving IOC IP: $ip"
            found_ioc_ips=1
        fi
    done
else
    echo "    [*] Could not collect connection data (no netstat/ss available)."
fi

if [ "$found_ioc_ips" -eq 0 ]; then
    echo "    [-] No active connections to known KadNap IOC IPs were found."
fi
echo ""

# 5. Check file hashes in common drop locations
echo "[+] Checking dropped-file hashes against known KadNap samples..."
IOC_HASHES="0b3dbb951de7a216dd5032d783ba7d0a5ecda2bf872643c3a4ddd1667fb38ffe ebf9de6b67e94b2bd2b0dcda1941e04fef1a1dad830404813e468ab8744b7ed8"
HASH_TOOL=""

if command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL="sha256sum"
elif command -v openssl >/dev/null 2>&1; then
    HASH_TOOL="openssl"
fi

found_ioc_hashes=0
if [ -n "$HASH_TOOL" ]; then
    for dir in /tmp /var/run; do
        if [ -d "$dir" ]; then
            for file in "$dir"/* "$dir"/.*; do
                if [ ! -f "$file" ]; then
                    continue
                fi

                if [ "$HASH_TOOL" = "sha256sum" ]; then
                    file_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
                else
                    file_hash=$(openssl dgst -sha256 "$file" 2>/dev/null | awk '{print $NF}')
                fi

                if [ -n "$file_hash" ] && echo "$IOC_HASHES" | grep -F "$file_hash" >/dev/null; then
                    echo "    [!] WARNING: File hash match for KadNap sample: $file"
                    echo "        SHA256: $file_hash"
                    found_ioc_hashes=1
                fi
            done
        fi
    done
else
    echo "    [*] No SHA256 utility available (sha256sum/openssl)."
fi

if [ "$found_ioc_hashes" -eq 0 ]; then
    echo "    [-] No known KadNap sample hashes found in /tmp or /var/run."
fi
echo ""

echo "=========================================================="
echo "Diagnostic complete. If any warnings [!] were triggered,  "
echo "your router may be compromised.                           "
echo "=========================================================="