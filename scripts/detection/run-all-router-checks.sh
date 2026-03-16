#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE="local"
SIMPLE=0
PROFILE_ARG=""
OUT_DIR="reports"

usage() {
    cat <<'EOF'
Usage:
  run-all-router-checks.sh [--mode local|remote] [--simple] [--profile <name-or-path>] [--out-dir <dir>]
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --simple)
            SIMPLE=1
            shift
            ;;
        --profile)
            PROFILE_ARG="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

TS=$(date +%Y%m%d-%H%M%S)
RUN_DIR="$OUT_DIR/$TS"
mkdir -p "$RUN_DIR"
SUMMARY_FILE="$RUN_DIR/summary.txt"
FINDINGS_FILE="$RUN_DIR/findings.log"

DETECTORS="audit-asuswrt-baseline.sh detect-kadnap.sh detect-kvbotnet.sh detect-zuorat.sh detect-hiatus.sh detect-mirai.sh detect-raptor-train.sh"

run_local() {
    detector="$1"
    out_file="$RUN_DIR/${detector%.sh}.log"
    SIMPLE_MODE="$SIMPLE" FINDINGS_LOG="$FINDINGS_FILE" "$SCRIPT_DIR/$detector" >"$out_file" 2>&1 || true
}

run_remote() {
    detector="$1"
    out_file="$RUN_DIR/${detector%.sh}.log"
    cmd="$SCRIPT_DIR/run-router-check.sh"
    if [ -n "$PROFILE_ARG" ]; then
        SIMPLE_MODE="$SIMPLE" "$cmd" --profile "$PROFILE_ARG" "$detector" >"$out_file" 2>&1 || true
    else
        SIMPLE_MODE="$SIMPLE" "$cmd" "$detector" >"$out_file" 2>&1 || true
    fi
}

for detector in $DETECTORS; do
    echo "Running: $detector"
    if [ "$MODE" = "remote" ]; then
        run_remote "$detector"
    else
        run_local "$detector"
    fi
done

high_count=$(grep -c '^high|' "$FINDINGS_FILE" 2>/dev/null || true)
medium_count=$(grep -c '^medium|' "$FINDINGS_FILE" 2>/dev/null || true)
low_count=$(grep -c '^low|' "$FINDINGS_FILE" 2>/dev/null || true)

if [ "$high_count" -eq 0 ] && [ "$medium_count" -eq 0 ] && [ "$low_count" -eq 0 ]; then
    # Fallback parser when detectors don't write structured findings (for example remote mode).
    high_count=$(grep -R -c '^    \[!\]' "$RUN_DIR" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
fi

{
    echo "Run directory: $RUN_DIR"
    echo "Mode: $MODE"
    echo "High findings: $high_count"
    echo "Medium findings: $medium_count"
    echo "Low findings: $low_count"
} >"$SUMMARY_FILE"

cat "$SUMMARY_FILE"

echo "Tip: export-report.sh $RUN_DIR"
