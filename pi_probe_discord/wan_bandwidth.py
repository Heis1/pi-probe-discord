"""FortiGate wan1 bandwidth sampling through read-only SNMPv3 authPriv."""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .fortigate_snmp import _secrets
from .storage import save_wan_bandwidth_sample

_IFNAME_OID = ".1.3.6.1.2.1.31.1.1.1.1"
_HC_IN_OID = ".1.3.6.1.2.1.31.1.1.1.6"
_HC_OUT_OID = ".1.3.6.1.2.1.31.1.1.1.10"
_UPTIME_OID = ".1.3.6.1.2.1.1.3.0"


def _command(config: Any, oids: list[str], walk: bool = False) -> list[str]:
    prefix = "PI_PROBE_FORTIGATE_SNMP"
    secret = _secrets(config.fortigate_secret_file, prefix)
    host = os.environ.get(f"{prefix}_HOST", "192.168.1.1").strip()
    timeout = max(1, int(os.environ.get(f"{prefix}_TIMEOUT_SECONDS", "3")))
    return ["snmpwalk" if walk else "snmpget", "-v3", "-l", "authPriv", "-u", secret[f"{prefix}_USERNAME"], "-a", secret[f"{prefix}_AUTH_PROTOCOL"], "-A", secret[f"{prefix}_AUTH_PASSWORD"], "-x", secret[f"{prefix}_PRIVACY_PROTOCOL"], "-X", secret[f"{prefix}_PRIVACY_PASSWORD"], "-t", str(timeout), "-r", "0", "-On", "-Oq", host, *oids]


def _run(config: Any, oids: list[str], walk: bool = False) -> tuple[bool, list[str], str]:
    try:
        timeout = max(1, int(os.environ.get("PI_PROBE_FORTIGATE_SNMP_TIMEOUT_SECONDS", "3")))
        result = subprocess.run(_command(config, oids, walk), text=True, capture_output=True, timeout=timeout + 3, check=False)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        return False, [], str(exc)[:180]
    if result.returncode:
        return False, [], (result.stderr or result.stdout or "SNMP query failed").strip()[:180]
    return True, result.stdout.splitlines(), ""


def _if_index(lines: list[str], interface: str) -> int | None:
    prefix = _IFNAME_OID + "."
    for line in lines:
        match = re.match(r"^" + re.escape(prefix) + r"(\d+)\s+(.+)$", line.strip())
        if match and match.group(2).strip().strip('"') == interface:
            return int(match.group(1))
    return None


def _integer(value: str) -> int | None:
    match = re.search(r"(-?\d+)", value)
    return int(match.group(1)) if match else None


def _read_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(state, handle, separators=(",", ":"))
        temporary = Path(handle.name)
    temporary.replace(path)


def collect_wan_bandwidth(config: Any, monotonic: Any = time.monotonic, now: Any = None) -> dict[str, Any]:
    """Take one sample. A rate exists only after two compatible counter reads."""
    now = now or (lambda: datetime.now().astimezone())
    state_path = Path(config.wan_bandwidth_state_json)
    if not config.wan_bandwidth_enabled:
        return {"enabled": False, "available": False, "status": "Not configured"}
    lock_path = state_path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"enabled": True, "available": False, "status": "Collection already running"}
        ok, lines, error = _run(config, [_IFNAME_OID], walk=True)
        if not ok:
            return {"enabled": True, "available": False, "status": "SNMP unavailable", "error": error}
        index = _if_index(lines, config.wan_bandwidth_interface)
        if index is None:
            return {"enabled": True, "available": False, "status": "Interface unavailable", "error": f"Interface {config.wan_bandwidth_interface} was not found"}
        ok, values, error = _run(config, [f"{_HC_IN_OID}.{index}", f"{_HC_OUT_OID}.{index}", _UPTIME_OID])
        if not ok or len(values) != 3:
            return {"enabled": True, "available": False, "status": "SNMP unavailable", "error": error or "SNMP returned an unexpected result"}
        inbound, outbound, uptime = (_integer(value) for value in values)
        if inbound is None or outbound is None or uptime is None:
            return {"enabled": True, "available": False, "status": "Invalid counter response"}
        measured_at = now()
        measured_monotonic = float(monotonic())
        previous = _read_state(state_path)
        base = {"enabled": True, "interface": config.wan_bandwidth_interface, "interfaceIndex": index, "checkedAt": measured_at.isoformat(), "lastSuccessAt": measured_at.isoformat(), "counterIn": inbound, "counterOut": outbound, "uptime": uptime, "monotonic": measured_monotonic}
        compatible = previous.get("interfaceIndex") == index and previous.get("uptime", uptime) <= uptime
        elapsed = measured_monotonic - float(previous.get("monotonic", measured_monotonic))
        delta_in = inbound - int(previous.get("counterIn", inbound))
        delta_out = outbound - int(previous.get("counterOut", outbound))
        if not compatible or elapsed <= 0 or delta_in < 0 or delta_out < 0:
            base.update({"available": False, "status": "Awaiting baseline", "downloadMbps": None, "uploadMbps": None})
            _write_state(state_path, base)
            return base
        download = delta_in * 8 / elapsed / 1_000_000
        upload = delta_out * 8 / elapsed / 1_000_000
        base.update({"available": True, "status": "Live", "downloadMbps": download, "uploadMbps": upload, "elapsedSeconds": elapsed})
        _write_state(state_path, base)
        save_wan_bandwidth_sample(config, measured_at, index, download, upload)
        return base


def load_wan_bandwidth_state(config: Any) -> dict[str, Any]:
    enabled = bool(getattr(config, "wan_bandwidth_enabled", False))
    path = getattr(config, "wan_bandwidth_state_json", "")
    state = _read_state(Path(path)) if path else {}
    return state if state else {"enabled": enabled, "available": False, "status": "No samples yet"}
