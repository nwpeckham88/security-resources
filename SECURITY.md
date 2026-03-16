# Security Policy

## Supported Scope
- All scripts under `scripts/detection/`
- IOC seed files under `iocs/`

## Reporting a Vulnerability
- Open a private security advisory if possible.
- Include reproduction steps, affected script path, and impact.
- Do not publish live secrets, credentials, or router public IPs.

## Handling Sensitive Data
- Avoid committing router credentials or private keys.
- Temporary password artifacts should be in memory-backed storage (`/dev/shm`) and short-lived.
- Redact customer/public IP data from shared reports unless needed.

## IOC Trust Model
- IOC updates should reference source and date.
- Prefer confidence-tagged entries and periodic cleanup of stale indicators.
