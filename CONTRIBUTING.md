# Contributing

## Development Guidelines
- Use POSIX shell (`/bin/sh`) for compatibility with BusyBox environments.
- Keep scripts read-only by default (no router config changes without explicit user action).
- Add comments only where logic is non-obvious.

## Before Opening a PR
- Run `sh tests/smoke.sh`
- Run `shellcheck` on changed scripts
- Validate new scripts have executable bit when intended

## IOC Curation
- Add entries to `iocs/<family>.txt` using prefixes:
  - `IP:`
  - `DOMAIN:`
  - `SHA256:`
  - `PORT:`
- Keep source and last-seen context in comments where available.

## Documentation
- Update `scripts/detection/ASUSWRT_MERLIN_BOTNET_RESEARCH.md` when adding major features.
