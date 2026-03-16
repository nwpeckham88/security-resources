# Home Router Incident Response

## Immediate Actions
- Disconnect router WAN temporarily if active compromise is suspected.
- Export config backup for analysis.
- Capture a baseline snapshot and run all detectors.

## Containment
- Disable remote admin and WAN SSH.
- Isolate suspicious clients.

## Eradication
- Factory reset router.
- Reflash latest firmware.
- Reconfigure manually from known-good settings (avoid importing old compromised configs).

## Recovery
- Rotate router admin password.
- Rotate Wi-Fi credentials.
- Regenerate SSH keys if used.
- Monitor with recurring detector runs.
