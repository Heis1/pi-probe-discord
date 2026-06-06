from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

from .config import DEFAULT_CONFIG_FILE, DEFAULT_DB_PATH


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

    checks.append(_check("data dir exists", db_path.parent.exists(), str(db_path.parent)))
    if db_path.parent.exists():
        writable = os.access(db_path.parent, os.W_OK)
        checks.append(_check("data dir writable", writable, str(db_path.parent)))

    db_ok = False
    if db_path.exists():
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("SELECT 1").fetchone()
            db_ok = True
        except sqlite3.Error as exc:
            checks.append(_check("database open", False, f"{db_path} ({exc})"))
    else:
        checks.append(_check("database exists", False, str(db_path)))
    if db_ok:
        checks.append(_check("database open", True, str(db_path)))

    services = [
        "pi-probe-discord-bot.service",
        "pi-probe-discord-snmp-listener.service",
        "pi-probe-discord-speedtest.timer",
        "pi-probe-discord-full.timer",
    ]
    for service in services:
        result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True, check=False)
        enabled = result.returncode == 0
        checks.append(_check(f"{service} enabled", enabled, result.stdout.strip() or result.stderr.strip() or "unknown"))

    required_sudo_cmds = [
        ["/bin/systemctl", "start", "--no-block", "pi-probe-discord-speedtest.service"],
        ["/bin/systemctl", "start", "--no-block", "pi-probe-discord-full.service"],
        ["/usr/bin/pi-probe-discord", "firewall"],
        ["/usr/bin/pi-probe-discord", "firewall-chart"],
        ["/usr/bin/pi-probe-discord", "router"],
    ]
    for cmd in required_sudo_cmds:
        result = subprocess.run(["sudo", "-n", "-l", *cmd], capture_output=True, text=True, check=False)
        allowed = result.returncode == 0
        checks.append(_check(f"sudo rule {' '.join(cmd)}", allowed, "allowed" if allowed else "missing"))

    failures = [line for ok, line in checks if not ok]
    lines = [line for _, line in checks]
    if failures:
        lines.append("")
        lines.append("Remediation:")
        lines.append("- Run: sudo visudo -f /etc/sudoers.d/pi-probe-discord-bot")
        lines.append("- Add missing NOPASSWD command lines from /usr/share/pi-probe-discord/pi-probe-discord-bot.sudoers.example")
        lines.append("- Ensure /etc/pi-probe-discord/pihole-update-discord.env is readable by bot user/group")
    return (1 if failures else 0), "\n".join(lines)
