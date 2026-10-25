"""Read-only FortiGate SNMPv3 collector.

Credentials are read only from the root-owned FortiGate secret file.  The
collector deliberately uses numeric OIDs and a short, no-retry timeout so a
missing SNMP service is reported as unavailable rather than stalling the
dashboard.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from .config import validate_router_webui_secret_file

_SYSTEM_OIDS = {
    "description": ".1.3.6.1.2.1.1.1.0",
    "uptime": ".1.3.6.1.2.1.1.3.0",
    "cpuPercent": ".1.3.6.1.4.1.12356.101.4.1.3.0",
    "memoryPercent": ".1.3.6.1.4.1.12356.101.4.1.4.0",
    "sessions": ".1.3.6.1.4.1.12356.101.4.1.8.0",
    "fortiOS": ".1.3.6.1.4.1.12356.101.4.1.1.0",
    "ipsDatabase": ".1.3.6.1.4.1.12356.101.4.2.2.0",
}


def _secrets(path_value: str, prefix: str = "PI_PROBE_FORTIGATE_SNMP") -> dict[str, str]:
    path = Path(path_value)
    validate_router_webui_secret_file(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    required = tuple(f"{prefix}_{suffix}" for suffix in ("USERNAME", "AUTH_PROTOCOL", "AUTH_PASSWORD", "PRIVACY_PROTOCOL", "PRIVACY_PASSWORD"))
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise RuntimeError("FortiGate SNMP credentials are not configured")
    return values


def _collect(config: Any, prefix: str, host_default: str) -> dict[str, Any]:
    if os.environ.get(f"{prefix}_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        return {"enabled": False, "available": False, "error": "Not configured", "metrics": {}}
    host = os.environ.get(f"{prefix}_HOST", host_default).strip()
    timeout = max(1, int(os.environ.get(f"{prefix}_TIMEOUT_SECONDS", "3")))
    try:
        secret = _secrets(config.fortigate_secret_file, prefix)
        command = ["snmpget", "-v3", "-l", "authPriv", "-u", secret[f"{prefix}_USERNAME"], "-a", secret[f"{prefix}_AUTH_PROTOCOL"], "-A", secret[f"{prefix}_AUTH_PASSWORD"], "-x", secret[f"{prefix}_PRIVACY_PROTOCOL"], "-X", secret[f"{prefix}_PRIVACY_PASSWORD"], "-t", str(timeout), "-r", "0", "-Oqv", host, *_SYSTEM_OIDS.values()]
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout + 3, check=False)
        if result.returncode != 0:
            return {"enabled": True, "available": False, "error": (result.stderr or result.stdout or "SNMP query failed").strip()[:180], "metrics": {}}
        values = result.stdout.splitlines()
        if len(values) != len(_SYSTEM_OIDS):
            return {"enabled": True, "available": False, "error": "SNMP returned an unexpected result", "metrics": {}}
        parsed = dict(zip(_SYSTEM_OIDS, values))
        for key in ("cpuPercent", "memoryPercent", "sessions"):
            try:
                parsed[key] = float(parsed[key])
            except (TypeError, ValueError):
                parsed[key] = None
        return {"enabled": True, "available": True, "error": "", "host": host, "metrics": parsed}
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        return {"enabled": True, "available": False, "error": str(exc)[:180], "metrics": {}}


def collect_fortigate_snmp_snapshot(config: Any) -> dict[str, Any]:
    return _collect(config, "PI_PROBE_FORTIGATE_SNMP", "192.168.1.1")


def collect_fortigate_30e_snmp_snapshot(config: Any) -> dict[str, Any]:
    return _collect(config, "PI_PROBE_FORTIGATE_30E_SNMP", "192.168.10.2")
