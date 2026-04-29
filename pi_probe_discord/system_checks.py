from __future__ import annotations

import shutil
import sqlite3
import subprocess
import time
import re
from datetime import datetime
from pathlib import Path

from .models import PiholeResult, UpdateResult


def _extract_pihole_update_status(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    update_lines = [line for line in lines if "update available" in line.lower()]
    if update_lines:
        return " | ".join(update_lines[:5])

    latest_lines = [line for line in lines if "latest:" in line.lower() and "version is" in line.lower()]
    parsed_updates: list[str] = []
    for line in latest_lines:
        match = re.search(r"^(.*?)\s+version\s+is\s+([^\s]+)\s+\(Latest:\s*([^)]+)\)", line, flags=re.IGNORECASE)
        if not match:
            continue
        component = match.group(1).strip().replace(" ", "")
        current = match.group(2).strip()
        latest = match.group(3).strip()
        if current.lstrip("vV") != latest.lstrip("vV"):
            parsed_updates.append(f"{component} {current}->{latest}")

    if parsed_updates:
        return " | ".join(parsed_updates[:5])
    return "Up to date"


def run_command(command: list[str], log_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if log_path is not None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {' '.join(command)}\n")
            if result.stdout:
                handle.write(result.stdout)
                if not result.stdout.endswith("\n"):
                    handle.write("\n")
            if result.stderr:
                handle.write(result.stderr)
                if not result.stderr.endswith("\n"):
                    handle.write("\n")
    return result


def run_updates(hostname: str, run_at_local: str, log_path: Path) -> UpdateResult:
    log_path.write_text(f"Running apt update and upgrade on {hostname} at {run_at_local}\n", encoding="utf-8")

    update = run_command(["sudo", "apt-get", "update"], log_path)
    if update.returncode != 0:
        return UpdateResult(ok=False, summary="Failed during package index refresh.", error="apt update failed")

    upgrade = run_command(["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "upgrade"], log_path)
    if upgrade.returncode != 0:
        return UpdateResult(ok=False, summary="Failed during package upgrade.", error="apt upgrade failed")

    packages: list[str] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("Inst "):
            parts = line.split()
            if len(parts) > 1:
                packages.append(parts[1])
    packages = sorted(set(packages))

    summary = "No package updates were available."
    if packages:
        summary = "\n".join(packages[:20])
        if len(packages) > 20:
            summary += f"\n... and {len(packages) - 20} more"
    return UpdateResult(ok=True, summary=summary, packages=packages)


def collect_pihole_info() -> PiholeResult:
    result = PiholeResult()

    if shutil.which("pihole") is None:
        result.warnings.append("Pi-hole command unavailable")
        return result

    if shutil.which("systemctl"):
        service = run_command(["systemctl", "is-active", "pihole-FTL"])
        state = service.stdout.strip()
        result.service_status = {
            "active": "Running",
            "inactive": "Stopped",
            "failed": "Failed",
            "activating": "Starting",
            "deactivating": "Stopping",
        }.get(state, "Unknown")

    status = run_command(["pihole", "status"])
    version_info = run_command(["pihole", "-v"])
    if status.returncode == 0:
        merged_output = status.stdout
        if version_info.returncode == 0:
            merged_output = f"{status.stdout}\n{version_info.stdout}"
        result.update_status = _extract_pihole_update_status(merged_output)
        output = status.stdout.lower()
        if "blocking is enabled" in output:
            result.blocking_status = "Enabled"
        elif "blocking is disabled" in output:
            result.blocking_status = "Disabled"
    else:
        result.warnings.append("pihole status failed")
        if version_info.returncode == 0:
            result.update_status = _extract_pihole_update_status(version_info.stdout)

    gravity_db = Path("/etc/pihole/gravity.db")
    if gravity_db.exists():
        modified = gravity_db.stat().st_mtime
        age_days = int(time.time() - modified) // 86400
        modified_text = datetime.fromtimestamp(modified).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        result.gravity_age = f"{age_days}d old ({modified_text})"

        try:
            with sqlite3.connect(gravity_db) as conn:
                row = conn.execute("SELECT COUNT(*) FROM gravity;").fetchone()
            if row and isinstance(row[0], int):
                result.blocklist_count = f"{row[0]} domains"
        except sqlite3.Error:
            result.warnings.append("Could not read gravity.db")
    else:
        result.warnings.append("gravity.db unavailable")
    return result
