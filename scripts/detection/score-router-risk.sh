#!/bin/sh

set -u

INPUT_FILE="${1:-}"
if [ -z "$INPUT_FILE" ] || [ ! -f "$INPUT_FILE" ]; then
    echo "Usage: score-router-risk.sh <findings-log-file>"
    exit 1
fi

high_count=$(grep -c '^high|' "$INPUT_FILE" 2>/dev/null || true)
medium_count=$(grep -c '^medium|' "$INPUT_FILE" 2>/dev/null || true)
low_count=$(grep -c '^low|' "$INPUT_FILE" 2>/dev/null || true)

score=$((high_count * 5 + medium_count * 2 + low_count))

level="low"
if [ "$score" -ge 15 ]; then
    level="critical"
elif [ "$score" -ge 8 ]; then
    level="high"
elif [ "$score" -ge 3 ]; then
    level="medium"
fi

echo "Risk score: $score"
echo "Risk level: $level"
echo "high findings: $high_count"
echo "medium findings: $medium_count"
echo "low findings: $low_count"
