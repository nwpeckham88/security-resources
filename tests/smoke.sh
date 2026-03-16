#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for script in \
  "$ROOT_DIR/scripts/detection/lib-router-detect.sh" \
  "$ROOT_DIR/scripts/detection/audit-asuswrt-baseline.sh" \
  "$ROOT_DIR/scripts/detection/detect-kadnap.sh" \
  "$ROOT_DIR/scripts/detection/detect-kvbotnet.sh" \
  "$ROOT_DIR/scripts/detection/detect-zuorat.sh" \
  "$ROOT_DIR/scripts/detection/detect-hiatus.sh" \
  "$ROOT_DIR/scripts/detection/detect-mirai.sh" \
  "$ROOT_DIR/scripts/detection/detect-raptor-train.sh" \
  "$ROOT_DIR/scripts/detection/setup-router-ssh.sh" \
  "$ROOT_DIR/scripts/detection/router-connect.sh" \
  "$ROOT_DIR/scripts/detection/run-router-check.sh" \
  "$ROOT_DIR/scripts/detection/run-all-router-checks.sh" \
  "$ROOT_DIR/scripts/detection/export-report.sh" \
  "$ROOT_DIR/scripts/detection/disable-router-ssh-reminder.sh" \
  "$ROOT_DIR/scripts/detection/capture-baseline.sh" \
  "$ROOT_DIR/scripts/detection/score-router-risk.sh" \
  "$ROOT_DIR/scripts/maintenance/update-iocs.sh"

do
  sh -n "$script"
done

echo "Smoke syntax checks passed."
