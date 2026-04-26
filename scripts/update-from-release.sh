#!/usr/bin/env bash
set -euo pipefail

REPO="Heis1/pi-probe-discord"
PACKAGE_NAME="pi-probe-discord"
TMP_DIR=""
RECONFIGURE=0

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage:
  scripts/update-from-release.sh latest
  scripts/update-from-release.sh 0.1.1
  scripts/update-from-release.sh /path/to/pi-probe-discord_0.1.1-1_all.deb
  scripts/update-from-release.sh https://github.com/.../pi-probe-discord_0.1.1-1_all.deb
  scripts/update-from-release.sh latest --reconfigure

What it does:
  1. Resolves a .deb from a local path, URL, or GitHub release.
  2. Installs it with apt.
  3. Runs systemctl daemon-reload.
  4. Restarts pi-probe-discord timers if they exist.
  5. Optionally reruns pi-probe-discord-install with --reconfigure.

Notes:
  - For private GitHub releases, use either:
      a) gh installed and authenticated on the Pi, or
      b) GITHUB_TOKEN exported in the shell.
  - For public releases, direct downloads work without auth.
EOF
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "Please run this script with sudo." >&2
        exit 1
    fi
}

require_tools() {
    local missing=()
    local tool
    for tool in apt-get systemctl python3 curl dpkg-deb; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

have_gh_auth() {
    command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1
}

make_tmp_dir() {
    if [[ -z "$TMP_DIR" ]]; then
        TMP_DIR="$(mktemp -d)"
    fi
}

download_url_to_file() {
    local url="$1"
    local destination="$2"
    curl -fL --retry 3 --connect-timeout 15 -o "$destination" "$url"
}

validate_deb_file() {
    local file_path="$1"
    if [[ ! -s "$file_path" ]]; then
        echo "Downloaded file is empty: $file_path" >&2
        return 1
    fi
    if ! dpkg-deb --info "$file_path" >/dev/null 2>&1; then
        echo "Downloaded file is not a valid Debian package: $file_path" >&2
        return 1
    fi
}

github_api_get() {
    local url="$1"
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        return 1
    fi
    curl -fsSL \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "$url"
}

resolve_release_version() {
    local selector="$1"
    if [[ "$selector" != "latest" ]]; then
        printf '%s\n' "$selector"
        return 0
    fi

    if have_gh_auth; then
        gh release view --repo "$REPO" --json tagName --jq '.tagName' | sed 's/^v//'
        return 0
    fi

    local payload
    payload="$(github_api_get "https://api.github.com/repos/${REPO}/releases/latest")" || {
        echo "Cannot resolve latest release. Use gh auth, export GITHUB_TOKEN, or pass a local .deb path." >&2
        return 1
    }
    PAYLOAD="$payload" python3 - <<'PY'
from __future__ import annotations
import json
import os
data = json.loads(os.environ["PAYLOAD"])
print(str(data["tag_name"]).removeprefix("v"))
PY
}

download_asset_from_release() {
    local version="$1"
    local destination="$2"
    local asset_name="${PACKAGE_NAME}_${version}-1_all.deb"
    local tag="v${version}"

    if have_gh_auth; then
        gh release download "$tag" \
            --repo "$REPO" \
            --pattern "$asset_name" \
            --dir "$(dirname "$destination")" \
            --clobber
        if [[ -f "$(dirname "$destination")/$asset_name" ]]; then
            mv "$(dirname "$destination")/$asset_name" "$destination"
            return 0
        fi
    fi

    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        local payload
        payload="$(github_api_get "https://api.github.com/repos/${REPO}/releases/tags/${tag}")" || true
        if [[ -n "$payload" ]]; then
            local asset_api_url
            asset_api_url="$(
                PAYLOAD="$payload" ASSET_NAME="$asset_name" python3 - <<'PY'
from __future__ import annotations
import json
import os
payload = json.loads(os.environ["PAYLOAD"])
asset_name = os.environ["ASSET_NAME"]
for asset in payload.get("assets", []):
    if asset.get("name") == asset_name:
        print(asset["url"])
        break
PY
            )"
            if [[ -n "$asset_api_url" ]]; then
                curl -fL \
                    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                    -H "Accept: application/octet-stream" \
                    -o "$destination" \
                    "$asset_api_url"
                return 0
            fi
        fi
    fi

    if ! download_url_to_file "https://github.com/${REPO}/releases/download/${tag}/${asset_name}" "$destination"; then
        echo "Could not download ${asset_name} from GitHub release ${tag}." >&2
        echo "If the repo is private, authenticate gh on the Pi or export GITHUB_TOKEN first." >&2
        return 1
    fi
}

resolve_deb_path() {
    local source="$1"
    make_tmp_dir

    if [[ -f "$source" ]]; then
        printf '%s\n' "$source"
        return 0
    fi

    local destination="$TMP_DIR/${PACKAGE_NAME}.deb"
    if [[ "$source" =~ ^https?:// ]]; then
        download_url_to_file "$source" "$destination"
        validate_deb_file "$destination"
        printf '%s\n' "$destination"
        return 0
    fi

    local version
    version="$(resolve_release_version "$source")" || return 1
    download_asset_from_release "$version" "$destination" || return 1
    validate_deb_file "$destination"
    printf '%s\n' "$destination"
}

restart_if_present() {
    local unit="$1"
    if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
        systemctl restart "$unit"
    fi
}

show_installed_version() {
    dpkg-query -W -f='${Version}\n' "$PACKAGE_NAME" 2>/dev/null || true
}

main() {
    if [[ $# -lt 1 || $# -gt 2 ]]; then
        usage >&2
        exit 1
    fi

    local source=""
    for arg in "$@"; do
        case "$arg" in
            --reconfigure)
                RECONFIGURE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                if [[ -n "$source" ]]; then
                    usage >&2
                    exit 1
                fi
                source="$arg"
                ;;
        esac
    done

    if [[ -z "$source" ]]; then
        usage >&2
        exit 1
    fi

    require_root
    require_tools

    local deb_path
    deb_path="$(resolve_deb_path "$source")"

    echo "Installing package from: $deb_path"
    apt-get install -y "$deb_path"

    systemctl daemon-reload
    restart_if_present "pi-probe-discord-speedtest.timer"
    restart_if_present "pi-probe-discord-full.timer"

    if [[ "$RECONFIGURE" -eq 1 ]]; then
        if command -v pi-probe-discord-install >/dev/null 2>&1; then
            pi-probe-discord-install
        else
            echo "pi-probe-discord-install not found after upgrade." >&2
            exit 1
        fi
    fi

    echo "Installed version: $(show_installed_version)"
    systemctl list-timers --all | grep 'pi-probe-discord' || true
}

main "$@"
