from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


def _devices(raw: str) -> list[dict[str, str]]:
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PI_PROBE_KEEPALIVE_DEVICES_JSON must be a JSON array.") from exc
    if not isinstance(items, list):
        raise RuntimeError("PI_PROBE_KEEPALIVE_DEVICES_JSON must be a JSON array.")
    devices: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        host = str(item.get("host") or "").strip()
        if name and host:
            devices.append({"name": name, "host": host, "role": str(item.get("role") or "router").strip()})
    return devices


def run_keepalive(config: Any, now: datetime | None = None) -> dict[str, Any]:
    measured_at = now or datetime.now().astimezone()
    results: list[dict[str, Any]] = []
    for device in _devices(config.keepalive_devices_json):
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
