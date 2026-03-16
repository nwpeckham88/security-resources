#!/bin/sh

set -u

PROFILE_PATH="${ROUTER_SSH_PROFILE:-$HOME/.config/security-resources/router-ssh-profile.env}"

usage() {
    cat <<'EOF'
Usage:
  router-connect.sh
  router-connect.sh --run "uname -a"
  router-connect.sh --profile /path/to/router-ssh-profile.env
EOF
}

load_profile() {
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
}

cleanup_expired_password() {
    if [ -z "${ROUTER_PASS_FILE:-}" ] || [ -z "${ROUTER_PASS_EXPIRES:-}" ]; then
        return
    fi

    now_ts=$(date +%s)
    if [ "$now_ts" -ge "$ROUTER_PASS_EXPIRES" ]; then
        if [ -f "$ROUTER_PASS_FILE" ]; then
            rm -f "$ROUTER_PASS_FILE"
        fi
        ROUTER_PASS_FILE=""
        ROUTER_PASS_EXPIRES=""
    fi
}

run_ssh() {
    ssh_opts="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts -p $ROUTER_PORT"
    if [ "$ROUTER_AUTH_MODE" = "key" ]; then
        if [ -z "${ROUTER_KEY_PATH:-}" ] || [ ! -f "$ROUTER_KEY_PATH" ]; then
            echo "Key auth selected but key file is missing: ${ROUTER_KEY_PATH:-<unset>}"
            exit 1
        fi
        ssh $ssh_opts -i "$ROUTER_KEY_PATH" "$ROUTER_USER@$ROUTER_HOST" "$@"
        return
    fi

    if [ "$ROUTER_AUTH_MODE" = "password" ]; then
        if [ -n "${ROUTER_PASS_FILE:-}" ] && [ -f "$ROUTER_PASS_FILE" ] && command -v sshpass >/dev/null 2>&1; then
            sshpass -f "$ROUTER_PASS_FILE" ssh $ssh_opts "$ROUTER_USER@$ROUTER_HOST" "$@"
            return
        fi
        ssh $ssh_opts "$ROUTER_USER@$ROUTER_HOST" "$@"
        return
    fi

    echo "Unsupported ROUTER_AUTH_MODE: $ROUTER_AUTH_MODE"
    exit 1
}

RUN_COMMAND=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile)
            PROFILE_PATH="$2"
            shift 2
            ;;
        --run)
            RUN_COMMAND="$2"
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

load_profile
cleanup_expired_password

if [ -n "$RUN_COMMAND" ]; then
    run_ssh "$RUN_COMMAND"
else
    run_ssh
fi
