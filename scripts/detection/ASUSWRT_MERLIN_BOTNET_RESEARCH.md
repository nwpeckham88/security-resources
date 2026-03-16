# ASUSWRT/Merlin Botnet Detection Research

Date: 2026-03-16
Scope: Botnet-focused detection on ASUSWRT and ASUSWRT-Merlin routers (BusyBox/Linux userland).

## Primary IOC Source

Reference repository:
- https://github.com/blacklotuslabs/IOCs

High-value router-relevant IOC files in that repo:
- `KadNap_IOCs.txt`
- `KVbotnet_IOCs.txt`
- `ZuoRAT_IoCs.txt`
- `Hiatus_2_IOCs.txt`
- `Raptor_Train_IOCs.txt`
- `Chaos_IoCs.txt`
- `Pumpkin_Eclipse_IOCs.txt`
- `Mirai_IoCs_Fate.txt`
- `AVrecon_IOCs.txt`
- `NSOCKS_IOCs.txt`

## Why These Families Matter On ASUSWRT/Merlin

Common overlap with ASUS/Merlin tradecraft:
- Multi-arch payloads (ARM, MIPS, x86 variants) targeting embedded Linux.
- Staging and execution from volatile paths like `/tmp`, `/var/run`, `/var/tmp`.
- Persistence via cron (`cru`/`crond`), startup scripts, or NVRAM-backed hooks.
- Command-and-control over direct IPs, generated domains, and odd port usage.
- Router proxying, tunneling, and botnet relay behavior (egress anomalies).

## Router-Centric Detection Surface (Scriptable)

## 1) Process and command-line anomalies

Collect:
- `ps w`

Look for:
- Unknown binaries executing from `/tmp`, `/var/run`, `/var/tmp`, `/dev/shm`.
- Suspicious names or masquerading (eg. hidden dotfiles, random short names).
- Download-and-exec one-liners (`wget|curl` piped to `sh`, `chmod +x` then exec).

## 2) Volatile and semi-persistent file artifacts

Collect:
- `find /tmp /var/run /var/tmp -maxdepth 3 -type f 2>/dev/null`
- `ls -la /jffs /jffs/scripts /jffs/configs 2>/dev/null`

Look for:
- Executables dropped in volatile dirs.
- Unexpected files in `/jffs/scripts` or `/jffs/configs` that launch binaries in `/tmp`.
- Known malware hashes from IOC feeds.

## 3) Persistence checks specific to ASUSWRT/Merlin

Collect:
- `crontab -l 2>/dev/null`
- `cru l 2>/dev/null` (Merlin utility)
- `nvram show 2>/dev/null | grep -Ei 'script|cmd|cron|wan|firewall|dnsmasq'`
- `ls -la /jffs/scripts 2>/dev/null`

Look for:
- Unauthorized cron entries, especially frequent execution loops.
- Malicious startup hooks in common Merlin script locations:
	- `/jffs/scripts/services-start`
	- `/jffs/scripts/wan-start`
	- `/jffs/scripts/firewall-start`
	- `/jffs/scripts/nat-start`
	- `/jffs/scripts/post-mount`

## 4) Network and C2 communication signals

Collect:
- `netstat -anp 2>/dev/null` (or `ss -antup` if available)
- `iptables -S 2>/dev/null`
- `iptables -t nat -S 2>/dev/null`
- `ip rule show 2>/dev/null`
- `ip route show table all 2>/dev/null`

Look for:
- Connections to IOC IPs/domains from Black Lotus Labs feeds.
- Unusual outbound connections from router-owned processes.
- Unauthorized NAT/REDIRECT rules indicating traffic hijack/proxy behavior.

## 5) DNS manipulation and resolver abuse

Collect:
- `cat /etc/resolv.conf 2>/dev/null`
- `cat /etc/dnsmasq.conf 2>/dev/null`
- `grep -R "server=" /jffs/configs 2>/dev/null`

Look for:
- Unexpected resolver changes.
- Malicious `dnsmasq` custom server directives.
- IOC domains in query logs if logging is enabled.

## Detection Priorities For Script Collection

## Priority 1: IOC network matching module

Input:
- IOC IP/domain lists from Black Lotus Labs text files.

Checks:
- Active sockets match IOC IPs.
- DNS cache/log hits for IOC domains.

Output:
- Severity-tagged findings with source family (KadNap/KVbotnet/etc).

## Priority 2: Persistence hunting module

Checks:
- `cru` + crontab entries.
- Merlin startup scripts and suspicious NVRAM command keys.

Output:
- Exact persistence path, command, and associated process/file.

## Priority 3: File/hash hunting module

Checks:
- Hash executables in `/tmp`, `/var/run`, `/var/tmp`, and suspicious `/jffs` paths.
- Compare against known SHA256 from IOC files.

Output:
- Matched hash, path, and likely malware family.

## Priority 4: Router behavior anomaly module

Checks:
- Unexpected listening ports.
- Burst outbound connections.
- Non-standard iptables NAT/redirect/proxy patterns.

Output:
- Triage clues when no direct IOC match is available.

## Initial Family-to-Detection Mapping

- KadNap:
	- Strong IOC support with current C2 IPs and hashes in `KadNap_IOCs.txt`.
	- Detect via active connection matching + temp file hash checks + cron/startup persistence.

- KVbotnet:
	- Router proxy C2 model and rich hash/cert IOC set in `KVbotnet_IOCs.txt`.
	- Detect via proxy-like egress + C2 IP matching + hash matching.

- ZuoRAT:
	- Explicit router sample references and router C2 VPS IOCs in `ZuoRAT_IoCs.txt`.
	- Detect via C2 matches and suspicious DNS/HTTP beacon patterns.

- Hiatus / HiatusRAT:
	- Router-oriented infrastructure and mips/mips64 hashes in `Hiatus_2_IOCs.txt`.
	- Detect via architecture-aware hash checks and heartbeat/upload server matches.

- Raptor Train / Nosedive indicators:
	- Includes IP/domain/tier infra and YARA-related string clues in `Raptor_Train_IOCs.txt`.
	- Detect via network IOC matching and shell-dropper behavior from `/tmp` and `/var/tmp`.

- Chaos/Kaiji/Mirai-adjacent:
	- Embedded Linux hashes and C2 data in `Chaos_IoCs.txt` and `Mirai_IoCs_Fate.txt`.
	- Detect via known C2 ports, dropped binaries, and telnet/SSH brute-force side effects.

## Known Constraints On Router Detection

- Minimal logging by default on consumer routers.
- BusyBox tool differences across firmware versions.
- Some models may lack `sha256sum`, `ss`, or full `iptables` visibility.

Implementation note:
- Detection scripts should gracefully degrade when tools are missing and still produce a useful report.

## Recommended Next Build Step

Create a shared library script first (eg. `lib-router-detect.sh`) with reusable functions:
- IOC loader/parser
- portable connection collector (`netstat`/`ss` fallback)
- hash function (`sha256sum`/`openssl` fallback)
- standardized finding output format

Then implement family scripts:
- `detect-kadnap.sh` (already started)
- `detect-kvbotnet.sh`
- `detect-zuorat.sh`
- `detect-hiatus.sh`

## Current Implementation Status

Implemented:
- `scripts/detection/lib-router-detect.sh`
- `scripts/detection/detect-kadnap.sh`
- `scripts/detection/detect-kvbotnet.sh`
- `scripts/detection/detect-zuorat.sh`
- `scripts/detection/detect-hiatus.sh`
- `scripts/detection/detect-mirai.sh`
- `scripts/detection/detect-raptor-train.sh`
- `scripts/detection/audit-asuswrt-baseline.sh`
- `scripts/detection/setup-router-ssh.sh`
- `scripts/detection/router-connect.sh`
- `scripts/detection/run-router-check.sh`
- `scripts/detection/run-all-router-checks.sh`
- `scripts/detection/export-report.sh`
- `scripts/detection/capture-baseline.sh`
- `scripts/detection/score-router-risk.sh`
- `scripts/detection/disable-router-ssh-reminder.sh`
- `scripts/maintenance/update-iocs.sh`
- `iocs/*.txt` seed IOC datasets
- `.github/workflows/ci.yml` + `tests/smoke.sh`
- `SECURITY.md`, `CONTRIBUTING.md`, `README.md`, and `docs/*`

Next recommended build target:
- Add confidence/date metadata fields to IOC seed entries and enforce schema linting.

