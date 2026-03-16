#!/bin/sh

set -u

CONFIG_DIR="$HOME/.config/security-resources"
PROFILE_PATH="$CONFIG_DIR/router-ssh-profile.env"

print_line() {
    printf '%s\n' "$1"
}

prompt() {
    label="$1"
    default_value="$2"
    printf '%s' "$label"
    if [ -n "$default_value" ]; then
        printf ' [%s]' "$default_value"
    fi
    printf ': '
    IFS= read -r value

    if [ -z "$value" ]; then
        value="$default_value"
    fi

    printf '%s' "$value"
}

generate_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 24 | tr -d '\n'
        return
    fi

    tr -dc 'A-Za-z0-9!@#$%^&*()-_=+[]{}' </dev/urandom | head -c 28
}

ensure_config_dir() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
}

save_profile() {
    host="$1"
    port="$2"
    user="$3"
    auth_mode="$4"
    key_path="$5"
    pass_file="$6"
    pass_expires="$7"

    ensure_config_dir

    cat >"$PROFILE_PATH" <<EOF
ROUTER_HOST='$host'
ROUTER_PORT='$port'
ROUTER_USER='$user'
ROUTER_AUTH_MODE='$auth_mode'
ROUTER_KEY_PATH='$key_path'
ROUTER_PASS_FILE='$pass_file'
ROUTER_PASS_EXPIRES='$pass_expires'
EOF

    chmod 600 "$PROFILE_PATH"
}

setup_key_auth() {
    default_key="$HOME/.ssh/id_ed25519"
    key_path=$(prompt "Path to SSH private key" "$default_key")

    if [ ! -f "$key_path" ]; then
        create_key=$(prompt "Key not found. Generate new ed25519 key now? (yes/no)" "yes")
        if [ "$create_key" = "yes" ]; then
            mkdir -p "$HOME/.ssh"
            chmod 700 "$HOME/.ssh"
            ssh-keygen -t ed25519 -a 100 -f "$key_path"
        else
            print_line "Cannot continue without a key file."
            exit 1
        fi
    fi

    if [ ! -f "$key_path.pub" ]; then
        print_line "Public key not found at $key_path.pub"
        exit 1
    fi

    print_line ""
    print_line "Copy this public key into your router SSH authorized keys setting:"
    print_line ""
    cat "$key_path.pub"
    print_line ""

    printf '%s' "$key_path"
}

setup_password_auth() {
    default_ttl="120"
    ttl_minutes=$(prompt "Temporary password storage duration in minutes" "$default_ttl")

    new_password=$(generate_password)

    print_line ""
    print_line "Generated strong SSH password:"
    print_line "$new_password"
    print_line ""
    print_line "Set this on the router from the web UI before connecting."
    print_line ""

    store_choice=$(prompt "Store this password temporarily for helper scripts? (yes/no)" "yes")
    if [ "$store_choice" != "yes" ]; then
        print_line "Password will not be stored."
        printf '%s|%s' "" ""
        return
    fi

    if [ ! -d /dev/shm ]; then
        print_line "Temporary in-memory storage /dev/shm is unavailable. Password not stored."
        printf '%s|%s' "" ""
        return
    fi

    pass_file="/dev/shm/router-ssh-pass-$$.txt"
    umask 177
    printf '%s\n' "$new_password" >"$pass_file"

    now_ts=$(date +%s)
    pass_expires=$((now_ts + (ttl_minutes * 60)))

    print_line "Password stored temporarily at: $pass_file"
    print_line "It expires at unix time: $pass_expires"
    print_line ""

    printf '%s|%s' "$pass_file" "$pass_expires"
}

print_line "=========================================================="
print_line " Router SSH Guided Setup"
print_line "=========================================================="
print_line ""
print_line "1) In ASUSWRT/Merlin web UI:"
print_line "   Administration -> System -> Enable SSH"
print_line "2) Prefer LAN-only SSH and disable WAN SSH unless required"
print_line "3) Prefer key authentication; use password only as fallback"
print_line ""

router_host=$(prompt "Router IP or hostname" "192.168.50.1")
router_port=$(prompt "Router SSH port" "22")
router_user=$(prompt "Router SSH username" "admin")
auth_mode=$(prompt "Authentication mode (key/password)" "key")

key_path=""
pass_file=""
pass_expires=""

if [ "$auth_mode" = "key" ]; then
    key_path=$(setup_key_auth)
elif [ "$auth_mode" = "password" ]; then
    password_setup=$(setup_password_auth)
    pass_file=$(printf '%s' "$password_setup" | awk -F'|' '{print $1}')
    pass_expires=$(printf '%s' "$password_setup" | awk -F'|' '{print $2}')
else
    print_line "Unsupported auth mode: $auth_mode"
    exit 1
fi

save_profile "$router_host" "$router_port" "$router_user" "$auth_mode" "$key_path" "$pass_file" "$pass_expires"

print_line "Profile saved to: $PROFILE_PATH"
print_line ""
print_line "Next steps:"
print_line "- Connect: scripts/detection/router-connect.sh"
print_line "- Run a remote check: scripts/detection/run-router-check.sh detect-kadnap.sh"
print_line ""
print_line "Security reminder: disable SSH when finished if you do not need continuous access."
