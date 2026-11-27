"""Small, read-only LG ThinQ Connect collector for the dashboard.

The API key below is LG's public ThinQ Connect SDK identifier, not a user
credential.  The account-specific PAT is only read from the root-owned secret
file and is never written to the state file or dashboard payload.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from .config import load_lg_thinq_secrets

_API_KEY = "v6GFvkweNo7DK7yD3ylIZ9w52aKBU0eJ7wLXkSR3"
_REFRIGERATOR = "DEVICE_REFRIGERATOR"


class LGThinQError(RuntimeError):
    pass


def _message_id() -> str:
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).rstrip(b"=").decode("ascii")


def _client_id(config: object) -> str:
    # Stable per Pi; ThinQ warns against continually creating new client IDs.
    seed = f"pi-probe-discord:{getattr(config, 'lg_thinq_state_json', '')}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _headers(config: object, pat: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {pat}",
        "x-country": str(getattr(config, "lg_thinq_country", "AU")).upper(),
        "x-message-id": _message_id(),
        "x-client-id": _client_id(config),
        "x-api-key": _API_KEY,
        "x-service-phase": "OP",
        "Accept": "application/json",
    }


def _request(config: object, pat: str, endpoint: str) -> Any:
    region = str(getattr(config, "lg_thinq_region", "kic")).lower()
    url = f"https://api-{region}.lgthinq.com/{endpoint.lstrip('/')}"
    try:
        response = requests.get(url, headers=_headers(config, pat), timeout=int(getattr(config, "lg_thinq_timeout_seconds", 10)))
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise LGThinQError(f"ThinQ request failed: {exc}") from exc
    if not response.ok:
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        message = error.get("message") or f"HTTP {response.status_code}"
        raise LGThinQError(f"ThinQ API error: {message}")
    return payload.get("response") if isinstance(payload, dict) else payload


def _value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _choose_refrigerator(config: object, devices: Any) -> dict[str, Any]:
    rows = devices if isinstance(devices, list) else []
    configured_id = str(getattr(config, "lg_thinq_device_id", "")).strip()
    model_hint = str(getattr(config, "lg_thinq_device_model", "")).strip().lower()
    refrigerators = [row for row in rows if isinstance(row, dict) and _REFRIGERATOR in _value(row, "deviceType", "device_type").upper()]
    if configured_id:
        refrigerators = [row for row in refrigerators if _value(row, "deviceId", "device_id", "id") == configured_id]
    if model_hint:
        matching = [row for row in refrigerators if model_hint in _value(row, "modelName", "model", "deviceModelName").lower()]
        refrigerators = matching or refrigerators
    if not refrigerators:
        raise LGThinQError("No matching refrigerator is available in the LG ThinQ account")
    return refrigerators[0]


def _read_status(status: Any) -> dict[str, Any]:
    data = status if isinstance(status, dict) else {}
    doors: list[str] = []
    for row in data.get("doorStatus", []) if isinstance(data.get("doorStatus"), list) else []:
        if isinstance(row, dict):
            state = _value(row, "doorState", "state")
            location = _value(row, "locationName", "location") or "Door"
            if state:
                doors.append(f"{location}: {state.title()}")
    temperatures: list[str] = []
    for row in data.get("temperature", []) if isinstance(data.get("temperature"), list) else []:
        if isinstance(row, dict):
            temperature = _value(row, "temperature", "currentTemperature", "temp")
            location = _value(row, "locationName", "location") or "Compartment"
            if temperature:
                temperatures.append(f"{location}: {temperature}")
    refrigeration = data.get("refrigeration") if isinstance(data.get("refrigeration"), dict) else {}
    return {
        "doors": doors,
        "temperatures": temperatures,
        "expressMode": refrigeration.get("expressMode"),
        "freshAirFilter": refrigeration.get("freshAirFilter", ""),
    }


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    temporary.replace(path)


def collect_lg_thinq_snapshot(config: object) -> dict[str, Any]:
    now = datetime.now().astimezone().isoformat()
    snapshot: dict[str, Any] = {"enabled": bool(getattr(config, "lg_thinq_enabled", False)), "checkedAt": now, "available": False, "error": "", "device": {}, "status": {}}
    if not snapshot["enabled"]:
        return snapshot
    try:
        pat = load_lg_thinq_secrets(config)["pat"]
        device = _choose_refrigerator(config, _request(config, pat, "devices"))
        device_id = _value(device, "deviceId", "device_id", "id")
        if not device_id:
            raise LGThinQError("ThinQ refrigerator has no device ID")
        snapshot["device"] = {"name": _value(device, "alias", "deviceName", "name") or "LG refrigerator", "model": _value(device, "modelName", "model", "deviceModelName")}
        snapshot["status"] = _read_status(_request(config, pat, f"devices/{device_id}/state"))
        snapshot["available"] = True
    except (LGThinQError, RuntimeError, KeyError) as exc:
        snapshot["error"] = str(exc)
    _write_state(Path(str(getattr(config, "lg_thinq_state_json"))), snapshot)
    return snapshot


def load_lg_thinq_state(config: object) -> dict[str, Any]:
    if not bool(getattr(config, "lg_thinq_enabled", False)):
        return {"enabled": False, "checkedAt": "", "available": False, "error": "", "device": {}, "status": {}}
    try:
        payload = json.loads(Path(str(getattr(config, "lg_thinq_state_json"))).read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except (OSError, json.JSONDecodeError):
        pass
    return {"enabled": True, "checkedAt": "", "available": False, "error": "No ThinQ status has been collected yet", "device": {}, "status": {}}
