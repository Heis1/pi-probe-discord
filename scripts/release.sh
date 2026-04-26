#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG_FILE="$ROOT_DIR/debian/changelog"
PACKAGE_NAME="pi-probe-discord"

usage() {
    cat <<'EOF'
Usage:
  scripts/release.sh "Release notes"
  scripts/release.sh --version 0.1.1 "Release notes"

Example:
  scripts/release.sh "Improve Discord chart readability"
  scripts/release.sh --version 0.2.0 "Add Pi upgrade helper"

What it does:
  1. Verifies the git worktree is clean.
  2. Derives the next version from debian/changelog unless --version is supplied.
  3. Updates debian/changelog to VERSION-1.
  4. Commits the release metadata.
  5. Creates git tag vVERSION.
  6. Builds the .deb with dpkg-buildpackage.
  7. Creates a GitHub release and uploads the .deb.

Default version bump:
  0.1.0 -> 0.1.1

The script currently auto-increments the patch version only.
If you want a minor or major bump, pass --version explicitly.
EOF
}

require_clean_tree() {
    if [[ -n "$(git -C "$ROOT_DIR" status --short)" ]]; then
        echo "Git worktree is not clean. Commit or stash changes before releasing." >&2
        exit 1
    fi
}

require_tools() {
    local missing=()
    local tool
    for tool in git dpkg-buildpackage gh python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

require_auth() {
    if ! gh auth status >/dev/null 2>&1; then
        echo "GitHub CLI is not authenticated. Run 'gh auth login' first." >&2
        exit 1
    fi
}

current_version() {
    CHANGELOG_FILE="$CHANGELOG_FILE" python3 - <<'PY'
from __future__ import annotations

import os
import re
from pathlib import Path

text = Path(os.environ["CHANGELOG_FILE"]).read_text().splitlines()[0]
match = re.search(r"\(([^)]+)\)", text)
if not match:
    raise SystemExit("Could not parse version from debian/changelog")
print(match.group(1).split("-", 1)[0])
PY
}

next_patch_version() {
    local version="$1"
    VERSION="$version" python3 - <<'PY'
from __future__ import annotations

import os

parts = os.environ["VERSION"].split(".")
if len(parts) != 3 or not all(part.isdigit() for part in parts):
    raise SystemExit(f"Unsupported version format: {os.environ['VERSION']}")
major, minor, patch = (int(part) for part in parts)
print(f"{major}.{minor}.{patch + 1}")
PY
}

resolve_version() {
    local explicit_version="${1:-}"
    if [[ -n "$explicit_version" ]]; then
        printf '%s\n' "$explicit_version"
        return 0
    fi

    local current
    current="$(current_version)"
    next_patch_version "$current"
}

validate_version() {
    local version="$1"
    VERSION="$version" python3 - <<'PY'
from __future__ import annotations

import os
import re

version = os.environ["VERSION"]
if not re.fullmatch(r"\d+\.\d+\.\d+", version):
    raise SystemExit(f"Unsupported version format: {version}")
PY
}

update_changelog() {
    local version="$1"
    local notes="$2"
    local timestamp
    timestamp="$(date -R)"

    VERSION="$version" NOTES="$notes" TIMESTAMP="$timestamp" CHANGELOG_FILE="$CHANGELOG_FILE" python3 - <<'PY'
from __future__ import annotations

import os
from pathlib import Path

version = os.environ["VERSION"]
notes = os.environ["NOTES"].strip()
timestamp = os.environ["TIMESTAMP"]
path = Path(os.environ["CHANGELOG_FILE"])
existing = path.read_text()

entry = f"""pi-probe-discord ({version}-1) unstable; urgency=medium

  * {notes}

 -- Codex Builder <noreply@example.invalid>  {timestamp}

"""

path.write_text(entry + existing)
PY
}

main() {
    local explicit_version=""
    local notes=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                if [[ $# -lt 2 ]]; then
                    usage >&2
                    exit 1
                fi
                explicit_version="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                if [[ -n "$notes" ]]; then
                    usage >&2
                    exit 1
                fi
                notes="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$notes" ]]; then
        usage >&2
        exit 1
    fi

    local version
    version="$(resolve_version "$explicit_version")"
    validate_version "$version"
    local tag="v$version"
    local artifact="../${PACKAGE_NAME}_${version}-1_all.deb"

    require_tools
    require_clean_tree
    require_auth

    if git -C "$ROOT_DIR" rev-parse "$tag" >/dev/null 2>&1; then
        echo "Tag $tag already exists." >&2
        exit 1
    fi

    echo "Releasing version: $version"

    update_changelog "$version" "$notes"

    git -C "$ROOT_DIR" add debian/changelog
    git -C "$ROOT_DIR" commit -m "Release $version"
    git -C "$ROOT_DIR" tag "$tag"

    (
        cd "$ROOT_DIR"
        dpkg-buildpackage -us -uc -b
    )

    if [[ ! -f "$ROOT_DIR/$artifact" && ! -f "$artifact" ]]; then
        echo "Expected build artifact not found: $artifact" >&2
        exit 1
    fi

    gh release create \
        "$tag" \
        "$artifact" \
        --repo "Heis1/${PACKAGE_NAME}" \
        --title "$tag" \
        --notes "$notes"

    echo "Release complete: $tag"
    echo "Artifact: $artifact"
}

main "$@"
