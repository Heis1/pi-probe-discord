from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import warnings
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from .config import load_fortigate_secrets
from .fortigate_snmp import collect_fortigate_30e_snmp_snapshot, collect_fortigate_snmp_snapshot


# FortiOS syslog is intentionally parsed conservatively. These categories
# describe what the firewall reported, rather than turning every deny (or a
# FortiGuard vulnerability association) into an incident.
_FORTI_FIELD_RE = re.compile(r'\b(?P<key>[A-Za-z_]+)=(?P<value>"[^"]*"|[^\s]+)')
_MAX_SYSLOG_READ_BYTES = 4 * 1024 * 1024


def _forti_fields(line: str) -> dict[str, str]:
    return {match.group("key").lower(): match.group("value").strip('"') for match in _FORTI_FIELD_RE.finditer(line)}


def classify_fortigate_event(line: str) -> str | None:
    """Return one operational category for a FortiOS syslog record.

    The precedence prevents one UTM session from being reported as several
    independent incidents. In particular, blocked DoH is policy enforcement,
    not a confirmed compromise.
    """
    fields = _forti_fields(line)
    if not fields:
        return None
    combined = " ".join(fields.get(key, "") for key in ("type", "subtype", "eventtype", "app", "appcat", "msg", "action")).lower()
    action = fields.get("action", "").lower()
    if "dns.over.https" in combined or "dns over https" in combined or "dns-over-https" in combined:
        return "dns_bypass_block" if action in {"block", "blocked", "deny", "denied"} else "dns_bypass_observed"
    if "ips" in combined or fields.get("subtype", "").lower() == "ips":
        return "ips_prevention" if action in {"block", "blocked", "deny", "denied", "reset"} else "ips_detection"
    if "virus" in combined or "malware" in combined:
        return "malware_prevention" if action in {"block", "blocked", "deny", "denied", "quarantine"} else "malware_detection"
    if "app-ctrl" in combined or "application" in combined:
        return "application_control_block" if action in {"block", "blocked", "deny", "denied"} else "application_control"
    if "login" in combined and ("fail" in combined or fields.get("status", "").lower() in {"fail", "failed"}):
        return "management_login_failure"
    if fields.get("type", "").lower() == "traffic" and action in {"deny", "denied", "block", "blocked"}:
        return "firewall_deny"
    return None


def summarise_fortigate_syslog(path_value: str, max_events: int = 20, window_hours: int = 24) -> dict[str, Any]:
    """Summarise a bounded, recent tail of received FortiGate syslog records."""
    path = Path(path_value)
    if not path.is_file():
        return {"available": False, "error": "FortiGate syslog is not available", "counts": {}, "recent": []}
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            if size > _MAX_SYSLOG_READ_BYTES:
                handle.seek(-_MAX_SYSLOG_READ_BYTES, 2)
                handle.readline()
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"available": False, "error": f"Could not read FortiGate syslog: {exc}", "counts": {}, "recent": []}
    now = datetime.now().astimezone()
    since = now - timedelta(hours=max(1, window_hours))
    counts: dict[str, int] = {}
    recent: list[dict[str, str]] = []
    for line in lines:
        # The bundled receiver prefixes each accepted packet with ISO-8601.
        # Ignore stale records rather than letting log retention inflate a
        # current security count. Legacy unprefixed records remain visible
        # until rotation, but are not treated as current telemetry.
        try:
            recorded_at = datetime.fromisoformat(line.split(maxsplit=1)[0])
        except ValueError:
            continue
        if recorded_at.tzinfo is None or recorded_at < since:
            continue
        category = classify_fortigate_event(line)
        if category is None:
            continue
        counts[category] = counts.get(category, 0) + 1
        fields = _forti_fields(line)
        recent.append({"category": category, "source": fields.get("srcip", ""), "destination": fields.get("dstip", ""), "policy": fields.get("policyid", ""), "action": fields.get("action", "")})
    return {"available": True, "error": "", "windowHours": max(1, window_hours), "counts": counts, "recent": recent[-max_events:]}


def wan_talkers_for_samples(path_value: str, sample_times: list[str], window_seconds: int = 15) -> dict[str, list[dict[str, Any]]]:
    """Attribute nearby completed WAN sessions to a sample without reading unbounded logs."""
    path = Path(path_value)
    if not path.is_file() or not sample_times:
        return {}
    events: list[dict[str, Any]] = []
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            if size > _MAX_SYSLOG_READ_BYTES:
                handle.seek(-_MAX_SYSLOG_READ_BYTES, 2); handle.readline()
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        try:
            recorded = datetime.fromisoformat(line.split(maxsplit=1)[0])
        except ValueError:
            continue
        fields = _forti_fields(line)
        if fields.get("type") == "traffic" and fields.get("subtype") == "forward" and fields.get("dstintf") == "wan1" and fields.get("srcip"):
            try: total = int(fields.get("sentbyte", "0")) + int(fields.get("rcvdbyte", "0"))
            except ValueError: total = 0
            events.append({"at": recorded.isoformat(), "ip": fields["srcip"], "name": fields.get("srcname", ""), "bytes": total})
    return wan_talkers_from_events(events, sample_times, window_seconds)


def wan_talkers_from_events(events: list[dict[str, Any]], sample_times: list[str], window_seconds: int = 15) -> dict[str, list[dict[str, Any]]]:
    """Attribute retained traffic events to nearby bandwidth samples."""
    parsed_samples: list[tuple[str, datetime]] = []
    for value in sample_times:
        try:
            parsed_samples.append((value, datetime.fromisoformat(value)))
        except ValueError:
            continue
    if not parsed_samples:
        return {}
    parsed_samples.sort(key=lambda item: item[1])
    sample_datetimes = [value for _, value in parsed_samples]
    window = timedelta(seconds=max(1, window_seconds))
    start = sample_datetimes[0] - window
    end = sample_datetimes[-1] + window
    buckets: dict[str, dict[str, dict[str, Any]]] = {value: {} for value, _ in parsed_samples}
    for event in events:
        try:
            recorded = datetime.fromisoformat(str(event.get("at") or ""))
        except ValueError:
            continue
        if recorded < start or recorded > end:
            continue
        source = str(event.get("ip") or "")
        if not source:
            continue
        # Associate each log record with the nearby chart interval. Binary
        # searches keep larger history views responsive.
        first = bisect_left(sample_datetimes, recorded - window)
        last = bisect_right(sample_datetimes, recorded + window)
        if first == last:
            continue
        try: total = int(event.get("bytes", 0))
        except ValueError: total = 0
        for sample, _ in parsed_samples[first:last]:
            row = buckets[sample].setdefault(source, {"ip": source, "name": str(event.get("name") or ""), "bytes": 0})
            row["bytes"] += max(0, total)
    return {sample: sorted(rows.values(), key=lambda row: row["bytes"], reverse=True)[:3] for sample, rows in buckets.items() if rows}


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
    snmp = collect_fortigate_snmp_snapshot(config)
    secondary_snmp = collect_fortigate_30e_snmp_snapshot(config)
    state: dict[str, Any] = {"enabled": bool(config.fortigate_enabled), "checkedAt": measured_at.isoformat(), "available": False, "error": "", "failureStage": "", "diagnostics": [], "system": {}, "metrics": {}, "security": summarise_fortigate_syslog(getattr(config, "fortigate_syslog_log_file", "")), "snmp": snmp, "secondary": secondary_snmp}
    if not config.fortigate_enabled:
        return state
    if snmp.get("available"):
        metrics = snmp.get("metrics") if isinstance(snmp.get("metrics"), dict) else {}
        state["available"] = True
        state["system"] = {"hostname": str(metrics.get("description") or "FortiGate"), "version": str(metrics.get("fortiOS") or "")}
        state["metrics"] = {key: metrics.get(key) for key in ("cpuPercent", "memoryPercent", "sessions")}
        path = Path(config.fortigate_state_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
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
    if snmp.get("available"):
        metrics = snmp.get("metrics") if isinstance(snmp.get("metrics"), dict) else {}
        state["available"] = True
        state["error"] = ""
        state["failureStage"] = ""
        state["system"].update({"hostname": str(metrics.get("description") or "FortiGate"), "version": str(metrics.get("fortiOS") or "")})
        state["metrics"].update({key: metrics.get(key) for key in ("cpuPercent", "memoryPercent", "sessions")})
    path = Path(config.fortigate_state_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def load_fortigate_state(config: Any) -> dict[str, Any]:
    if not config.fortigate_enabled:
        return {"enabled": False, "checkedAt": "", "available": False, "error": "", "failureStage": "", "diagnostics": [], "system": {}, "metrics": {}, "security": {"available": False, "counts": {}, "recent": []}}
    try:
        value = json.loads(Path(config.fortigate_state_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict):
        return {}
    # Security logs advance independently of the one-minute API poll.  This
    # bounded local read keeps the read-only dashboard current without adding
    # FortiGate requests for every browser refresh.
    value["security"] = summarise_fortigate_syslog(getattr(config, "fortigate_syslog_log_file", ""))
    return value
