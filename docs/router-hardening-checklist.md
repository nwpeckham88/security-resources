# Router Hardening Checklist (ASUSWRT/Merlin)

- Keep firmware current.
- Disable WAN admin and WAN SSH unless required.
- Use key-based SSH and disable password auth when possible.
- Restrict SSH access to LAN addresses.
- Rotate admin/SSH passwords after incident response work.
- Review `/jffs/scripts` for unexpected startup hooks.
- Review DNS settings (`/etc/resolv.conf`, `dnsmasq` overrides).
- Re-run baseline and IOC checks after each configuration change.
