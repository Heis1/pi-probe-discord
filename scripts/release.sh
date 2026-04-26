#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG_FILE="$ROOT_DIR/debian/changelog"
PACKAGE_NAME="pi-probe-discord"

usage() {
    cat <<'EOF'
Usage:
  scripts/release.sh VERSION "Release notes"

Example:
  scripts/release.sh 0.1.1 "Improve Discord chart readability"

What it does:
  1. Verifies the git worktree is clean.
  2. Updates debian/changelog to VERSION-1.
  3. Commits the release metadata.
  4. Creates git tag vVERSION.
  5. Builds the .deb with dpkg-buildpackage.
  6. Creates a GitHub release and uploads the .deb.
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
    if [[ $# -ne 2 ]]; then
        usage >&2
        exit 1
    fi

    local version="$1"
    local notes="$2"
    local tag="v$version"
    local artifact="../${PACKAGE_NAME}_${version}-1_all.deb"

    require_tools
    require_clean_tree
    require_auth

    if git -C "$ROOT_DIR" rev-parse "$tag" >/dev/null 2>&1; then
        echo "Tag $tag already exists." >&2
        exit 1
    fi

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
