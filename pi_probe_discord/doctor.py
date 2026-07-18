from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

from .config import DEFAULT_CONFIG_FILE, DEFAULT_DB_PATH, load_dotenv_style


def _check(name: str, ok: bool, detail: str) -> tuple[bool, str]:
    status = "OK" if ok else "FAIL"
    return ok, f"[{status}] {name}: {detail}"


def run_doctor() -> tuple[int, str]:
    checks: list[tuple[bool, str]] = []
    config_path = Path(os.environ.get("CONFIG_FILE", str(DEFAULT_CONFIG_FILE)))
    db_path = Path(os.environ.get("DB_PATH", str(DEFAULT_DB_PATH)))

    checks.append(_check("config file exists", config_path.exists(), str(config_path)))
    if config_path.exists():
        readable = os.access(config_path, os.R_OK)
        checks.append(_check("config file readable", readable, str(config_path)))
        if readable:
            load_dotenv_style(config_path)

    data_dir_exists = False
    try:
        data_dir_exists = db_path.parent.exists()
    except PermissionError:
        data_dir_exists = False
    checks.append(_check("data dir exists", data_dir_exists, str(db_path.parent)))
    if data_dir_exists:
        writable = os.access(db_path.parent, os.W_OK)
        checks.append(_check("data dir writable", writable, str(db_path.parent)))

    db_ok = False
    db_exists = False
    try:
        db_exists = db_path.exists()
    except PermissionError:
        checks.append(_check("database exists", False, f"{db_path} (permission denied)"))
    if db_exists:
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("SELECT 1").fetchone()
            db_ok = True
        except PermissionError:
            checks.append(_check("database open", False, f"{db_path} (permission denied)"))
        except sqlite3.Error as exc:
            checks.append(_check("database open", False, f"{db_path} ({exc})"))
    elif not any("database exists" in line for _, line in checks):
        checks.append(_check("database exists", False, str(db_path)))
    if db_ok:
        checks.append(_check("database open", True, str(db_path)))

    services = [
        "pi-probe-discord-bot.service",
        "pi-probe-discord-speedtest.timer",
        "pi-probe-discord-full.timer",
        "pi-probe-discord-nmap.timer",
    ]
    if os.environ.get("PI_PROBE_ROUTER_SNMP_LISTENER_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
        services.append("pi-probe-discord-snmp-listener.service")
    for service in services:
        result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True, check=False)
        enabled = result.returncode == 0
        checks.append(_check(f"{service} enabled", enabled, result.stdout.strip() or result.stderr.strip() or "unknown"))

    failures = [line for ok, line in checks if not ok]
    lines = [line for _, line in checks]
    if failures:
        lines.append("")
        lines.append("Remediation:")
        lines.append("- Ensure /etc/pi-probe-discord/pihole-update-discord.env and pi-probe-discord-bot.env are owned by root:pi-probe-discord with mode 640")
    return (1 if failures else 0), "\n".join(lines)
