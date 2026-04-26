#!/usr/bin/env bash

# Raspberry Pi / Pi-hole updater with Discord reporting.
# - Loads webhook config from environment or a local env file.
# - Runs apt update + upgrade and summarizes upgraded packages.
# - Collects Pi-hole status details when available.
# - Posts a single Discord embed with success, warning, or error state.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/pihole-update-discord.env}"
LOG_FILE="${LOG_FILE:-/tmp/pihole-update-discord.log}"
HOSTNAME="$(hostname)"
RUN_AT_LOCAL="$(date '+%Y-%m-%d %H:%M:%S %Z')"
RUN_AT_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Load optional local config without requiring secrets in the script.
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    . "$CONFIG_FILE"
    set +a
fi

WEBHOOK_URL="${WEBHOOK_URL:-${DISCORD_WEBHOOK_URL:-}}"

if [[ -z "$WEBHOOK_URL" ]]; then
    echo "WEBHOOK_URL is not set. Export it or create $CONFIG_FILE" >&2
    exit 1
fi

have_command() {
    command -v "$1" >/dev/null 2>&1
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

# Keep long package lists readable inside Discord field limits.
format_package_summary() {
    local -n package_ref=$1
    local limit=20
    local count="${#package_ref[@]}"
    local output=""
    local index

    if (( count == 0 )); then
        printf 'No packages were upgraded.'
        return
    fi

    for (( index = 0; index < count && index < limit; index++ )); do
        output+="${package_ref[index]}"$'\n'
    done

    if (( count > limit )); then
        output+="... and $((count - limit)) more"
    else
        output="${output%$'\n'}"
    fi

    printf '%s' "$output"
}

# Gather Pi-hole service and gravity details without failing the whole run.
collect_pihole_info() {
    PIHOLE_SERVICE_STATUS="Unknown"
    PIHOLE_BLOCKING_STATUS="Unknown"
    PIHOLE_GRAVITY_AGE="Unavailable"
    PIHOLE_BLOCKLIST_COUNT="Unavailable"
    PIHOLE_WARNING=""

    if ! have_command pihole; then
        PIHOLE_WARNING="Pi-hole command unavailable"
        return
    fi

    if have_command systemctl; then
        local service_state
        service_state="$(systemctl is-active pihole-FTL 2>/dev/null || true)"
        case "$service_state" in
            active) PIHOLE_SERVICE_STATUS="Running" ;;
            inactive) PIHOLE_SERVICE_STATUS="Stopped" ;;
            failed) PIHOLE_SERVICE_STATUS="Failed" ;;
            activating) PIHOLE_SERVICE_STATUS="Starting" ;;
            deactivating) PIHOLE_SERVICE_STATUS="Stopping" ;;
            *) PIHOLE_SERVICE_STATUS="Unknown" ;;
        esac
    fi

    local status_output status_rc
    status_output="$(pihole status 2>&1)"
    status_rc=$?
    if (( status_rc == 0 )); then
        if grep -qi "blocking is enabled" <<<"$status_output"; then
            PIHOLE_BLOCKING_STATUS="Enabled"
        elif grep -qi "blocking is disabled" <<<"$status_output"; then
            PIHOLE_BLOCKING_STATUS="Disabled"
        fi
    else
        PIHOLE_WARNING="$(trim "${PIHOLE_WARNING} ${PIHOLE_WARNING:+| }pihole status failed")"
    fi

    local gravity_db="/etc/pihole/gravity.db"
    if [[ -f "$gravity_db" ]]; then
        local gravity_mtime now_epoch age_seconds age_days gravity_local_time
        gravity_mtime="$(stat -c '%Y' "$gravity_db" 2>/dev/null || true)"
        if [[ "$gravity_mtime" =~ ^[0-9]+$ ]]; then
            now_epoch="$(date +%s)"
            age_seconds=$((now_epoch - gravity_mtime))
            age_days=$((age_seconds / 86400))
            gravity_local_time="$(date -d "@$gravity_mtime" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || true)"
            PIHOLE_GRAVITY_AGE="${age_days}d old (${gravity_local_time:-mtime unavailable})"
        fi

        if have_command sqlite3; then
            local blocklist_count
            blocklist_count="$(sqlite3 "$gravity_db" 'SELECT COUNT(*) FROM gravity;' 2>/dev/null || true)"
            if [[ "$blocklist_count" =~ ^[0-9]+$ ]]; then
                PIHOLE_BLOCKLIST_COUNT="$blocklist_count domains"
            fi
        else
            PIHOLE_WARNING="$(trim "${PIHOLE_WARNING} ${PIHOLE_WARNING:+| }sqlite3 unavailable")"
        fi
    else
        PIHOLE_WARNING="$(trim "${PIHOLE_WARNING} ${PIHOLE_WARNING:+| }gravity.db unavailable")"
    fi
}

# Run package updates and capture a concise package summary.
run_updates() {
    UPDATE_RESULT="success"
    UPDATE_SUMMARY=""
    UPDATE_ERROR=""
    UPDATED_PACKAGES=()

    : >"$LOG_FILE"
    printf 'Running apt update and upgrade on %s at %s\n' "$HOSTNAME" "$RUN_AT_LOCAL" >>"$LOG_FILE"

    if ! sudo apt-get update >>"$LOG_FILE" 2>&1; then
        UPDATE_RESULT="error"
        UPDATE_ERROR="apt update failed"
        UPDATE_SUMMARY="Failed during package index refresh."
        return
    fi

    if ! sudo env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade >>"$LOG_FILE" 2>&1; then
        UPDATE_RESULT="error"
        UPDATE_ERROR="apt upgrade failed"
        UPDATE_SUMMARY="Failed during package upgrade."
        return
    fi

    mapfile -t UPDATED_PACKAGES < <(grep '^Inst ' "$LOG_FILE" | awk '{print $2}' | sort -u)

    if (( ${#UPDATED_PACKAGES[@]} == 0 )); then
        UPDATE_SUMMARY="No package updates were available."
    else
        UPDATE_SUMMARY="$(format_package_summary UPDATED_PACKAGES)"
    fi
}

build_payload() {
    local status_label status_icon color description details
    details=""

    case "$UPDATE_RESULT" in
        error)
            status_label="Error"
            status_icon="❌"
            color=15158332
            description="$UPDATE_ERROR"
            ;;
        *)
            if [[ -n "$PIHOLE_WARNING" ]]; then
                status_label="Warning"
                status_icon="⚠️"
                color=16776960
                description="Update completed with partial Pi-hole information."
            else
                status_label="Success"
                status_icon="✅"
                color=3066993
                description="Update completed successfully."
            fi
            ;;
    esac

    if [[ -n "$PIHOLE_WARNING" ]]; then
        details="Pi-hole notes: $PIHOLE_WARNING"
    else
        details="Pi-hole information collected successfully."
    fi

    PAYLOAD_JSON="$(
        STATUS_LABEL="$status_label" \
        STATUS_ICON="$status_icon" \
        EMBED_COLOR="$color" \
        DESCRIPTION="$description" \
        DETAILS="$details" \
        HOST_VALUE="$HOSTNAME" \
        RUN_AT_LOCAL_VALUE="$RUN_AT_LOCAL" \
        PIHOLE_SERVICE_VALUE="$PIHOLE_SERVICE_STATUS" \
        PIHOLE_BLOCKING_VALUE="$PIHOLE_BLOCKING_STATUS" \
        PIHOLE_GRAVITY_VALUE="$PIHOLE_GRAVITY_AGE" \
        PIHOLE_BLOCKLIST_VALUE="$PIHOLE_BLOCKLIST_COUNT" \
        UPDATE_SUMMARY_VALUE="$UPDATE_SUMMARY" \
        LOG_FILE_VALUE="$LOG_FILE" \
        RUN_AT_UTC_VALUE="$RUN_AT_UTC" \
        python3 <<'PY'
import json
import os

payload = {
    "embeds": [
        {
            "title": f"{os.environ['STATUS_ICON']} Pi-hole Update Report",
            "description": (
                f"**Status:** {os.environ['STATUS_LABEL']}\n"
                f"{os.environ['DESCRIPTION']}\n"
                f"{os.environ['DETAILS']}"
            ),
            "color": int(os.environ["EMBED_COLOR"]),
            "fields": [
                {"name": "Hostname", "value": f"`{os.environ['HOST_VALUE']}`", "inline": True},
                {"name": "Date/Time", "value": os.environ["RUN_AT_LOCAL_VALUE"], "inline": True},
                {"name": "Pi-hole Service", "value": os.environ["PIHOLE_SERVICE_VALUE"], "inline": True},
                {"name": "Blocking", "value": os.environ["PIHOLE_BLOCKING_VALUE"], "inline": True},
                {"name": "Gravity Age", "value": os.environ["PIHOLE_GRAVITY_VALUE"], "inline": True},
                {"name": "Blocklist", "value": os.environ["PIHOLE_BLOCKLIST_VALUE"], "inline": True},
                {"name": "Recent Update Summary", "value": f"```text\n{os.environ['UPDATE_SUMMARY_VALUE']}\n```", "inline": False},
            ],
            "footer": {"text": f"log: {os.environ['LOG_FILE_VALUE']}"},
            "timestamp": os.environ["RUN_AT_UTC_VALUE"],
        }
    ]
}

print(json.dumps(payload))
PY
    )"
}

# Post one webhook payload and fail loudly if Discord rejects it.
send_webhook() {
    if ! curl --silent --show-error --fail-with-body \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$PAYLOAD_JSON" \
        "$WEBHOOK_URL"; then
        echo "Discord webhook POST failed" >&2
        return 1
    fi
}

main() {
    if ! have_command python3; then
        echo "python3 is required to build the Discord JSON payload" >&2
        exit 1
    fi

    collect_pihole_info
    run_updates
    build_payload

    if ! send_webhook; then
        exit 1
    fi
}

main "$@"
