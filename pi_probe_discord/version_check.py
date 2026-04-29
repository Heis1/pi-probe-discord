from __future__ import annotations

import os
import re
import subprocess
from typing import Final

import requests

DEFAULT_REPO: Final[str] = "Heis1/pi-probe-discord"


def _parse_semver(value: str) -> tuple[int, int, int] | None:
    cleaned = value.strip().lstrip("v")
    cleaned = cleaned.split("-", 1)[0]
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", cleaned)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def current_version() -> str | None:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "pi-probe-discord"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def latest_release_version(timeout: int = 8) -> str | None:
    repo = os.environ.get("PI_PROBE_DISCORD_REPO", DEFAULT_REPO).strip() or DEFAULT_REPO
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException:
        return None
    payload = response.json()
    tag = payload.get("tag_name")
    if not isinstance(tag, str):
        return None
    return tag.strip()


def version_status_line(timeout: int = 8) -> str:
    current = current_version()
    latest = latest_release_version(timeout=timeout)
    if current is None:
        return "Probe version: unknown"
    if latest is None:
        return f"Probe version: {current} · GitHub latest: unavailable"

    current_semver = _parse_semver(current)
    latest_semver = _parse_semver(latest)
    if current_semver is None or latest_semver is None:
        return f"Probe version: {current} · GitHub latest: {latest}"
    if current_semver < latest_semver:
        return f"Update available: {current} -> {latest}"
    return f"Probe up to date: {current} ({latest})"
