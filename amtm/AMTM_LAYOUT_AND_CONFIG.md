# AMTM Layout and Config Draft

Date: 2026-03-16
Status: Draft schema and file layout

## Repository Layout (planned)
- `amtm/AMTM_PLAN.md`
- `amtm/AMTM_LAYOUT_AND_CONFIG.md`
- `amtm/install.sh` (future)
- `amtm/uninstall.sh` (future)
- `amtm/menu.sh` (future)

## Router Deploy Layout (planned)
- `/jffs/addons/security-resources/bin/`
- `/jffs/addons/security-resources/iocs/`
- `/jffs/addons/security-resources/state/`
- `/jffs/addons/security-resources/reports/`
- `/jffs/addons/security-resources/config/security-resources.conf`

## Config Schema (draft)
`security-resources.conf`:
- `ENABLED=1`
- `RUN_MODE=full`
- `QUICK_SCHEDULE=*/60 * * * *`
- `FULL_SCHEDULE=30 3 * * *`
- `ALERT_THRESHOLD=high`
- `ALERT_ON_CLEAR=0`
- `REPORT_RETENTION=30`
- `NOTIFY_BACKENDS=local`
- `EMAIL_TO=`
- `TELEGRAM_BOT_TOKEN=`
- `TELEGRAM_CHAT_ID=`
- `WEBHOOK_URL=`

## State Files (draft)
- `state/last_run.status`
- `state/last_run.timestamp`
- `state/last_findings.sha256`
- `state/lock.pid`

## Cron Jobs (draft)
- `securityres_quick`: quick profile run
- `securityres_full`: full profile run

## Notification Policy (draft)
- Trigger if finding severity >= `ALERT_THRESHOLD`.
- Trigger when finding fingerprint is new.
- Suppress repeated identical finding sets.

## Future Deliverables
- Installer with idempotent behavior.
- Config wizard for menu mode.
- Backend-specific notifier scripts.
- Router-safe report exporter.
