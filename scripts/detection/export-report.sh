#!/bin/sh

set -u

RUN_DIR="${1:-}"
if [ -z "$RUN_DIR" ] || [ ! -d "$RUN_DIR" ]; then
    echo "Usage: export-report.sh <run-directory>"
    exit 1
fi

FINDINGS="$RUN_DIR/findings.log"
SUMMARY="$RUN_DIR/summary.txt"
JSON_OUT="$RUN_DIR/report.json"
MD_OUT="$RUN_DIR/report.md"

high_count=$(grep -c '^high|' "$FINDINGS" 2>/dev/null || true)
medium_count=$(grep -c '^medium|' "$FINDINGS" 2>/dev/null || true)
low_count=$(grep -c '^low|' "$FINDINGS" 2>/dev/null || true)

{
    echo "{"
    echo "  \"runDir\": \"$RUN_DIR\"," 
    echo "  \"counts\": {"
    echo "    \"high\": $high_count,"
    echo "    \"medium\": $medium_count,"
    echo "    \"low\": $low_count"
    echo "  },"
    echo "  \"findings\": ["
    first=1
    if [ -f "$FINDINGS" ]; then
        while IFS='|' read -r sev msg; do
            [ -z "$sev" ] && continue
            esc_msg=$(printf '%s' "$msg" | sed 's/"/\\"/g')
            if [ "$first" -eq 0 ]; then
                echo ","
            fi
            printf "    {\"severity\": \"%s\", \"message\": \"%s\"}" "$sev" "$esc_msg"
            first=0
        done <"$FINDINGS"
    fi
    echo ""
    echo "  ]"
    echo "}"
} >"$JSON_OUT"

{
    echo "# Router Security Report"
    echo ""
    echo "Run directory: \`$RUN_DIR\`"
    if [ -f "$SUMMARY" ]; then
        echo ""
        sed 's/^/- /' "$SUMMARY"
    fi
    echo ""
    echo "## Findings"
    if [ -f "$FINDINGS" ]; then
        sed 's/^/- /' "$FINDINGS"
    else
        echo "- none"
    fi
} >"$MD_OUT"

echo "Exported: $JSON_OUT"
echo "Exported: $MD_OUT"
