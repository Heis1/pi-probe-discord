from __future__ import annotations

import json
import socket
import ssl
import subprocess
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from .config import load_fortigate_secrets


class FortigateProbeError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def _number(value: Any) -> float | None:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


def _resource_current(payload: dict[str, Any], resource: str) -> float | None:
    results = payload.get("results", {})
    rows = results.get(resource, []) if isinstance(results, dict) else []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return _number(rows[0].get("current"))
    return _number(results.get(resource) if isinstance(results, dict) else None)


def _base_url(value: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise FortigateProbeError("configuration", "FORTIGATE_BASE_URL must be an https URL.")
    return value.rstrip("/"), parsed.hostname, parsed.port or 443


def _diagnostic(stage: str, ok: bool, message: str) -> dict[str, Any]:
    return {"stage": stage, "ok": ok, "message": message[:300]}


def _route_diagnostic(host: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(["ip", "route", "get", host], text=True, capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Could not inspect route: {exc}"
    output = (result.stdout or result.stderr).strip().splitlines()
    return (result.returncode == 0, output[0] if output else "No route returned")


def _tcp_diagnostic(host: str, port: int, timeout: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connection to {host}:{port} established"
    except socket.gaierror as exc:
        return False, f"DNS resolution failed: {exc}"
    except OSError as exc:
        return False, f"TCP connection failed: {exc}"


def _tls_diagnostic(host: str, port: int, timeout: int, verify: str | bool) -> tuple[bool, str]:
    try:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
        if verify is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                return True, f"TLS negotiated: {tls_socket.version() or 'unknown version'}"
    except ssl.SSLError as exc:
        return False, f"TLS verification or negotiation failed: {exc}"
    except OSError as exc:
        return False, f"TLS connection failed: {exc}"


def _request_json(session: requests.Session, base_url: str, path: str, params: dict[str, str], timeout: int, verify: str | bool) -> dict[str, Any]:
    try:
        with warnings.catch_warnings():
            if verify is False:
                warnings.simplefilter("ignore", requests.packages.urllib3.exceptions.InsecureRequestWarning)
            response = session.get(f"{base_url}{path}", params=params, timeout=(timeout, timeout), verify=verify)
    except requests.exceptions.SSLError as exc:
        raise FortigateProbeError("tls", f"HTTPS/TLS request failed: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise FortigateProbeError("tcp", f"HTTPS connection failed: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise FortigateProbeError("http", f"FortiGate API request timed out: {exc}") from exc
    except requests.RequestException as exc:
        raise FortigateProbeError("http", f"FortiGate API request failed: {exc}") from exc
    if response.status_code in {401, 403}:
        raise FortigateProbeError("authentication", f"FortiGate rejected API credentials (HTTP {response.status_code}).")
    if response.status_code >= 400:
        raise FortigateProbeError("http", f"FortiGate API returned HTTP {response.status_code} for {path}.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise FortigateProbeError("parsing", f"FortiGate API returned invalid JSON for {path}.") from exc
    if not isinstance(payload, dict):
        raise FortigateProbeError("parsing", f"FortiGate API returned an unexpected JSON shape for {path}.")
    if str(payload.get("status", "success")).lower() not in {"success", ""}:
        raise FortigateProbeError("api", f"FortiGate API reported {payload.get('status')} for {path}.")
    return payload


def collect_fortigate_snapshot(config: Any, now: datetime | None = None) -> dict[str, Any]:
    measured_at = now or datetime.now().astimezone()
    state: dict[str, Any] = {"enabled": bool(config.fortigate_enabled), "checkedAt": measured_at.isoformat(), "available": False, "error": "", "failureStage": "", "diagnostics": [], "system": {}, "metrics": {}}
    if not config.fortigate_enabled:
        return state
    try:
        base_url, host, port = _base_url(config.fortigate_url)
        route_ok, route_message = _route_diagnostic(host)
        state["diagnostics"].append(_diagnostic("route", route_ok, route_message))
        if not route_ok:
            raise FortigateProbeError("route", route_message)
        tcp_ok, tcp_message = _tcp_diagnostic(host, port, config.fortigate_timeout_seconds)
        state["diagnostics"].append(_diagnostic("tcp", tcp_ok, tcp_message))
        if not tcp_ok:
            raise FortigateProbeError("tcp", tcp_message)
        verify: str | bool = (
            config.fortigate_ca_file if config.fortigate_tls_verify and config.fortigate_ca_file else bool(config.fortigate_tls_verify)
        )
        if isinstance(verify, str) and not Path(verify).is_file():
            raise FortigateProbeError("tls", f"FortiGate CA file not found: {verify}")
        if verify is False:
            state["diagnostics"].append(_diagnostic("tls", True, "TLS certificate verification is disabled by explicit configuration."))
        else:
            tls_ok, tls_message = _tls_diagnostic(host, port, config.fortigate_timeout_seconds, verify)
            state["diagnostics"].append(_diagnostic("tls", tls_ok, tls_message))
            if not tls_ok:
                raise FortigateProbeError("tls", tls_message)
        token = load_fortigate_secrets(config)["api_token"]
        common = {"access_token": token, "vdom": config.fortigate_vdom}
        session = requests.Session()
        status = _request_json(session, base_url, "/api/v2/monitor/system/status", common, config.fortigate_timeout_seconds, verify)
        state["diagnostics"].append(_diagnostic("api", True, "FortiGate REST API responded and authentication succeeded."))
        cpu = _request_json(session, base_url, "/api/v2/monitor/system/resource/usage", {**common, "resource": "cpu", "interval": "1-min"}, config.fortigate_timeout_seconds, verify)
        mem = _request_json(session, base_url, "/api/v2/monitor/system/resource/usage", {**common, "resource": "mem", "interval": "1-min"}, config.fortigate_timeout_seconds, verify)
        sessions = _request_json(session, base_url, "/api/v2/monitor/system/resource/usage", {**common, "resource": "session", "interval": "1-min"}, config.fortigate_timeout_seconds, verify)
        result = status.get("results", {}) if isinstance(status.get("results"), dict) else {}
        state.update({"available": True, "system": {key: result.get(key) for key in ("hostname", "version", "serial", "model_name", "model") if result.get(key) is not None}, "metrics": {"cpuPercent": _resource_current(cpu, "cpu"), "memoryPercent": _resource_current(mem, "mem"), "sessions": _resource_current(sessions, "session")}})
    except FortigateProbeError as exc:
        state["failureStage"] = exc.stage
        state["error"] = str(exc)[:300]
    except (OSError, RuntimeError, ValueError) as exc:
        state["failureStage"] = "configuration"
        state["error"] = str(exc)[:300]
    path = Path(config.fortigate_state_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def load_fortigate_state(config: Any) -> dict[str, Any]:
    if not config.fortigate_enabled:
        return {"enabled": False, "checkedAt": "", "available": False, "error": "", "failureStage": "", "diagnostics": [], "system": {}, "metrics": {}}
    try:
        value = json.loads(Path(config.fortigate_state_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = {}
    return value if isinstance(value, dict) else {}
