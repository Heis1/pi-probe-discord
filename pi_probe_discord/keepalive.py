from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


def _disabled_hosts_path(config: Any) -> Path:
    """Store dashboard-controlled exclusions beside the writable state file."""
    return Path(config.keepalive_state_json).parent / "disabled-hosts.json"


def _disabled_hosts(config: Any) -> set[str]:
    try:
        payload = json.loads(_disabled_hosts_path(config).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(payload, list):
        return set()
    return {str(host).strip() for host in payload if str(host).strip()}


def _devices(raw: str, disabled_hosts: set[str] | None = None) -> list[dict[str, Any]]:
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PI_PROBE_KEEPALIVE_DEVICES_JSON must be a JSON array.") from exc
    if not isinstance(items, list):
        raise RuntimeError("PI_PROBE_KEEPALIVE_DEVICES_JSON must be a JSON array.")
    disabled_hosts = disabled_hosts or set()
    devices: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        host = str(item.get("host") or "").strip()
        if name and host:
            configured_enabled = item.get("pingEnabled", True) is not False
            devices.append({
                "name": name,
                "host": host,
                "role": str(item.get("role") or "router").strip(),
                "pingEnabled": configured_enabled and host not in disabled_hosts,
            })
    return devices


def set_device_ping_enabled(config: Any, host: str, enabled: bool) -> None:
    """Persist a per-device toggle without modifying the protected env file."""
    host = host.strip()
    configured_hosts = {device["host"] for device in _devices(config.keepalive_devices_json)}
    if not host or host not in configured_hosts:
        raise RuntimeError("Keep-alive device is not configured.")
    path = _disabled_hosts_path(config)
    disabled_hosts = _disabled_hosts(config)
    if enabled:
        disabled_hosts.discard(host)
    else:
        disabled_hosts.add(host)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(sorted(disabled_hosts), indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_keepalive(config: Any, now: datetime | None = None) -> dict[str, Any]:
    measured_at = now or datetime.now().astimezone()
    results: list[dict[str, Any]] = []
    for device in _devices(config.keepalive_devices_json, _disabled_hosts(config)):
        if not device["pingEnabled"]:
            results.append({**device, "up": None, "latencyMs": None, "error": "Ping checks disabled"})
            continue
        try:
            completed = subprocess.run(
                ["ping", "-n", "-c", "1", "-W", str(config.keepalive_timeout_seconds), device["host"]],
                capture_output=True,
                text=True,
                timeout=config.keepalive_timeout_seconds + 2,
                check=False,
            )
            output = f"{completed.stdout}\n{completed.stderr}"
            latency = None
            if "time=" in output:
                latency = round(float(output.split("time=", 1)[1].split()[0].replace("ms", "")), 2)
            results.append({**device, "up": completed.returncode == 0, "latencyMs": latency, "error": "" if completed.returncode == 0 else "No ICMP reply"})
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            results.append({**device, "up": False, "latencyMs": None, "error": str(exc)[:160]})
    state = {"checkedAt": measured_at.isoformat(), "enabled": config.keepalive_enabled, "devices": results}
    path = Path(config.keepalive_state_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def load_keepalive_state(config: Any) -> dict[str, Any]:
    if not config.keepalive_enabled:
        return {"enabled": False, "checkedAt": "", "devices": []}
    try:
        state = json.loads(Path(config.keepalive_state_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"enabled": True, "checkedAt": "", "devices": []}
    return state if isinstance(state, dict) else {"enabled": True, "checkedAt": "", "devices": []}
