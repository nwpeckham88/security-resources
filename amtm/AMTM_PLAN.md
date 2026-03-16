# AMTM Integration Plan

Date: 2026-03-16
Status: Planning only (no implementation yet)

## Goal
Run router security checks on ASUSWRT/Merlin via AMTM on a schedule, and notify only when meaningful findings occur.

## Objectives
- Provide an AMTM-friendly install/update/uninstall flow.
- Schedule checks via `cru` (quick and full profiles).
- Persist state to avoid duplicate alert noise.
- Send notifications through configurable backends.
- Keep BusyBox compatibility and safe defaults.

## Proposed Phases

## 1) AMTM Packaging and Runtime Split
- Add router-focused runtime bundle compatible with `/bin/sh` on BusyBox.
- Keep host-focused tooling separate from router-native execution path.
- Use addon root path: `/jffs/addons/security-resources`.

## 2) Installer/Updater
- Create install script to:
  - create addon directories
  - deploy scripts and IOC seed files
  - initialize config/state files
  - set executable permissions
- Create update script to refresh scripts and IOC data.

## 3) Scheduling
- Add scheduler setup using `cru`.
- Preset schedules:
  - hourly quick + daily full
  - daily full only
  - custom cron expression
- Add lock file support to prevent overlapping runs.

## 4) Stateful Alerting
- Persist previous finding fingerprints.
- Alert only on:
  - new findings
  - severity increase
  - optional clear-state notices
- Add severity threshold (`low`, `medium`, `high`).

## 5) Notification Backends
- Local file/log output (default).
- Email backend (if configured).
- Telegram webhook backend.
- Generic webhook backend.

## 6) AMTM Menu UX
- Menu actions:
  - Install/Update
  - Configure schedule
  - Configure notifications
  - Run now
  - View last report
  - Show status
  - Uninstall
- Keep beginner-friendly prompts and safe defaults.

## 7) Reporting and Retention
- Store run outputs under `/jffs/addons/security-resources/reports`.
- Write `latest.json` and `latest.md` pointers.
- Retain last N runs (default: 30).

## 8) Validation Matrix
- Test on multiple ASUSWRT-Merlin versions.
- Test with/without Entware.
- Validate behavior after reboot.
- Validate duplicate-alert suppression and threshold rules.

## Risks and Constraints
- BusyBox utility differences across models/firmware.
- Limited storage under `/jffs` on some devices.
- Notification dependencies may not exist by default.

## Exit Criteria
- One-command install from AMTM-compatible context.
- Scheduled runs execute reliably after reboot.
- Alerts are deduplicated and actionable.
- Reports are human-readable and exportable.
