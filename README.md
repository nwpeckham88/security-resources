# security-resources

Router-focused security checks and IOC-driven detection scripts with a focus on ASUSWRT/Merlin environments.

## Quick Start
1. `scripts/detection/setup-router-ssh.sh`
2. `scripts/detection/run-all-router-checks.sh --mode remote --profile home`
3. `scripts/detection/export-report.sh reports/<timestamp>`

## Key Paths
- Detectors: `scripts/detection/`
- IOC seeds: `iocs/`
- Research notes: `scripts/detection/ASUSWRT_MERLIN_BOTNET_RESEARCH.md`
- Hardening docs: `docs/`

## CI
- GitHub Actions runs syntax checks and shellcheck on push/PR.
