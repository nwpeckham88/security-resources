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

echo "=========================================================="
echo "Diagnostic complete. If any warnings [!] were triggered,  "
echo "your router may be compromised.                           "
echo "=========================================================="