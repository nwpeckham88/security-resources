#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROFILE_PATH="${ROUTER_SSH_PROFILE:-$HOME/.config/security-resources/router-ssh-profile.env}"
SIMPLE_MODE="${SIMPLE_MODE:-0}"

resolve_profile_path() {
    profile_arg="$1"
    case "$profile_arg" in
        */*)
            printf '%s' "$profile_arg"
            ;;
        *)
            printf '%s/.config/security-resources/%s.env' "$HOME" "$profile_arg"
            ;;
    esac
}

usage() {
    cat <<'EOF'
Usage:
    run-router-check.sh [--profile <name-or-path>] [--simple] <detector-script>
Examples:
  run-router-check.sh detect-kadnap.sh
    run-router-check.sh --profile home --simple detect-kvbotnet.sh
  run-router-check.sh detect-kvbotnet.sh
  run-router-check.sh audit-asuswrt-baseline.sh
EOF
}

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

if [ "$1" = "--profile" ]; then
    PROFILE_PATH=$(resolve_profile_path "$2")
    shift 2
fi

if [ "$1" = "--simple" ]; then
    SIMPLE_MODE=1
    shift
fi

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

TARGET_SCRIPT="$1"
if [ ! -f "$TARGET_SCRIPT" ]; then
    TARGET_SCRIPT="$SCRIPT_DIR/$1"
fi

if [ ! -f "$TARGET_SCRIPT" ]; then
    echo "Detector script not found: $1"
    exit 1
fi

LIB_SCRIPT="$SCRIPT_DIR/lib-router-detect.sh"
if [ ! -f "$LIB_SCRIPT" ]; then
    echo "Missing shared library: $LIB_SCRIPT"
    exit 1
fi

if [ ! -f "$PROFILE_PATH" ]; then
    echo "Profile not found: $PROFILE_PATH"
    echo "Run scripts/detection/setup-router-ssh.sh first."
    exit 1
fi

# shellcheck disable=SC1090
. "$PROFILE_PATH"

: "${ROUTER_HOST:?Missing ROUTER_HOST in profile}"
: "${ROUTER_PORT:?Missing ROUTER_PORT in profile}"
: "${ROUTER_USER:?Missing ROUTER_USER in profile}"
: "${ROUTER_AUTH_MODE:?Missing ROUTER_AUTH_MODE in profile}"

now_ts=$(date +%s)
if [ -n "${ROUTER_PASS_EXPIRES:-}" ] && [ "$now_ts" -ge "$ROUTER_PASS_EXPIRES" ]; then
    if [ -n "${ROUTER_PASS_FILE:-}" ] && [ -f "$ROUTER_PASS_FILE" ]; then
        rm -f "$ROUTER_PASS_FILE"
    fi
    ROUTER_PASS_FILE=""
fi

SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts -p $ROUTER_PORT"
SCP_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts -P $ROUTER_PORT"

run_ssh() {
    if [ "$ROUTER_AUTH_MODE" = "key" ]; then
        if [ -z "${ROUTER_KEY_PATH:-}" ] || [ ! -f "$ROUTER_KEY_PATH" ]; then
            echo "Key auth selected but key file is missing: ${ROUTER_KEY_PATH:-<unset>}"
            exit 1
        fi
        ssh $SSH_OPTS -i "$ROUTER_KEY_PATH" "$ROUTER_USER@$ROUTER_HOST" "$@"
        return
    fi

    if [ "$ROUTER_AUTH_MODE" = "password" ]; then
        if [ -n "${ROUTER_PASS_FILE:-}" ] && [ -f "$ROUTER_PASS_FILE" ] && command -v sshpass >/dev/null 2>&1; then
            sshpass -f "$ROUTER_PASS_FILE" ssh $SSH_OPTS "$ROUTER_USER@$ROUTER_HOST" "$@"
            return
        fi
        ssh $SSH_OPTS "$ROUTER_USER@$ROUTER_HOST" "$@"
        return
    fi

    echo "Unsupported ROUTER_AUTH_MODE: $ROUTER_AUTH_MODE"
    exit 1
}

run_scp() {
    if [ "$ROUTER_AUTH_MODE" = "key" ]; then
        scp $SCP_OPTS -i "$ROUTER_KEY_PATH" "$@"
        return
    fi

    if [ "$ROUTER_AUTH_MODE" = "password" ]; then
        if [ -n "${ROUTER_PASS_FILE:-}" ] && [ -f "$ROUTER_PASS_FILE" ] && command -v sshpass >/dev/null 2>&1; then
            sshpass -f "$ROUTER_PASS_FILE" scp $SCP_OPTS "$@"
            return
        fi
        scp $SCP_OPTS "$@"
        return
    fi

    echo "Unsupported ROUTER_AUTH_MODE: $ROUTER_AUTH_MODE"
    exit 1
}

REMOTE_BASE="/tmp/router-check-$$"
REMOTE_LIB="$REMOTE_BASE/lib-router-detect.sh"
REMOTE_SCRIPT="$REMOTE_BASE/$(basename "$TARGET_SCRIPT")"

# Upload helper library and target script.
run_ssh "mkdir -p '$REMOTE_BASE'"
run_scp "$LIB_SCRIPT" "$TARGET_SCRIPT" "$ROUTER_USER@$ROUTER_HOST:$REMOTE_BASE/"

# Execute and clean up.
run_ssh "chmod +x '$REMOTE_SCRIPT' '$REMOTE_LIB' && SIMPLE_MODE='$SIMPLE_MODE' '$REMOTE_SCRIPT'; rc=\$?; rm -rf '$REMOTE_BASE'; exit \$rc"
