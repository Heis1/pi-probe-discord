from __future__ import annotations

import fcntl
import json
import os
import shlex
import subprocess
import sys
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from textwrap import shorten
import xml.etree.ElementTree as ET

from .models import AppConfig


VALID_CATEGORIES = {
    "infrastructure",
    "servers",
    "computers",
    "mobile",
    "media",
    "iot",
    "printer",
    "unknown",
}

BBL_ISSUER_MARKERS = (
    "bbl technologies co. ltd",
    "bbl device ca",
    "bbl ca",
)
BBL_SERIAL_RE = re.compile(r"^[0-9A-Z]{10,}$")
IP_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:\s*\(.*\))?$")


def _first_text(element: ET.Element | None, xpath: str, default: str = "") -> str:
    if element is None:
        return default
    found = element.find(xpath)
    if found is None:
        return default
    return (found.text or "").strip()


def _is_ip_like_name(value: str) -> bool:
    return bool(IP_LIKE_RE.fullmatch(value.strip()))


def _summarize_reasons(reasons: list[str], *, limit: int = 2) -> str:
    compact = [reason for reason in reasons if reason][:limit]
    return " · ".join(compact)


def _contains_phrase(text: str, *phrases: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    padded = f" {normalized} "
    for phrase in phrases:
        target = re.sub(r"[^a-z0-9]+", " ", phrase.lower()).strip()
        if target and f" {target} " in padded:
            return True
    return False


def _friendly_name_from_signals(hostname: str, vendor: str, category: str, text: str, fallback: str) -> str:
    if _contains_phrase(text, "iphone"):
        return "Apple iPhone"
    if _contains_phrase(text, "ipad"):
        return "Apple iPad"
    if _contains_phrase(text, "samsung", "galaxy") and category == "mobile":
        return "Samsung Phone"
    if _contains_phrase(text, "pixel") and category == "mobile":
        return "Google Pixel Phone"
    if _contains_phrase(text, "tcl", "smart tv", "android tv") and category == "media":
        return "TCL Smart TV"
    if _contains_phrase(text, "firestick", "fire tv") and category == "media":
        return "Amazon Fire TV"
    if _contains_phrase(text, "nintendo switch") and category == "media":
        return "Nintendo Switch"
    if _contains_phrase(text, "chromecast") and category == "media":
        return "Google Chromecast"
    if _contains_phrase(text, "google nest") and category in {"media", "iot"}:
        return "Google Nest Device"
    if _contains_phrase(text, "google home") and category in {"media", "iot"}:
        return "Google Home Device"
    if _contains_phrase(text, "eufy homebase") and category == "iot":
        return "Eufy HomeBase"
    if _contains_phrase(text, "eufy") and _contains_phrase(text, "camera") and category == "iot":
        return "Eufy Camera"
    if _contains_phrase(text, "lenovo") and category == "computers":
        return "Lenovo Computer"
    if _contains_phrase(text, "dell") and category == "computers":
        return "Dell Computer"
    if fallback and not _is_ip_like_name(fallback):
        return fallback
    if vendor.strip():
        return vendor.strip()
    if hostname.strip() and hostname.strip() != fallback:
        return hostname.strip()
    return fallback


def _rank_category_signals(
    hostname: str,
    vendor: str,
    host_os_text: str,
    ip: str,
    port_entries: list[dict[str, object]],
) -> tuple[str, int, list[str]]:
    port_numbers = {int(item.get("port") or 0) for item in port_entries}
    services = [
        str(item.get("service") or "")
        for item in port_entries
        if str(item.get("service") or "").strip()
    ]
    script_text = " ".join(str(item.get("scriptText") or "") for item in port_entries if str(item.get("scriptText") or "").strip())
    text = " ".join(
        part
        for part in (
            hostname,
            vendor,
            host_os_text,
            " ".join(services),
            script_text,
        )
        if part
    ).lower()
    scores: dict[str, int] = {category: 0 for category in VALID_CATEGORIES}
    reasons: dict[str, list[str]] = {category: [] for category in VALID_CATEGORIES}

    def add(category: str, points: int, reason: str) -> None:
        scores[category] += points
        reasons[category].append(reason)

    if ip.endswith(".1"):
        add("infrastructure", 80, "Gateway-style .1 address")
    if any(token in text for token in ("router", "gateway", "archer", "ubiquiti", "unifi")):
        add("infrastructure", 60, "Router or gateway identifier present")
    if vendor and any(token in vendor.lower() for token in ("tp-link", "ubiquiti", "mikrotik")):
        add("infrastructure", 25, "Infrastructure vendor match")
    if {53, 67, 68}.intersection(port_numbers):
        add("infrastructure", 25, "Core network service ports exposed")

    if _contains_phrase(text, "pi hole", "pihole", "server", "nas", "proxmox", "docker", "raspberry", "pi probe", "synology"):
        add("servers", 55, "Server-oriented hostname or vendor signal")
    if {22, 53, 80, 443}.intersection(port_numbers) and _contains_phrase(text, "server", "nas", "raspberry", "pi hole", "pihole"):
        add("servers", 30, "Common server ports paired with server keywords")

    if _contains_phrase(text, "iphone", "ipad", "pixel", "android", "phone", "samsung", "galaxy"):
        add("mobile", 70, "Mobile device keyword present")

    if _contains_phrase(text, "tv", "smart tv", "chromecast", "roku", "apple tv", "fire tv", "firestick", "playstation", "xbox", "nintendo switch", "google home", "google nest"):
        add("media", 70, "Media device keyword present")
    if {8008, 8009}.intersection(port_numbers):
        add("media", 30, "Cast-style media control ports exposed")

    if _contains_phrase(text, "laptop", "desktop", "pc", "lenovo", "thinkpad", "yoga", "macbook", "workstation", "dell", "latitude", "xps", "inspiron"):
        add("computers", 70, "Computer keyword present")
    if 3389 in port_numbers or 5900 in port_numbers:
        add("computers", 25, "Remote desktop port exposed")

    if _contains_phrase(text, "printer", "camera", "plug", "switch", "echo", "ring", "vacuum", "iot", "tuya", "shelly", "eufy", "homebase", "nest cam"):
        add("iot", 55, "IoT-oriented device keyword present")
    if {554, 8080, 9100, 515, 631}.intersection(port_numbers):
        add("iot", 30, "Common IoT or embedded service ports exposed")

    ranked = max(
        ((category, score) for category, score in scores.items() if category != "unknown"),
        key=lambda item: item[1],
        default=("unknown", 0),
    )
    category, score = ranked
    if score < 30:
        return "unknown", 0, []
    return category, score, reasons[category]


def _category_label(category: str) -> str:
    return {
        "infrastructure": "Infrastructure",
        "servers": "Servers",
        "computers": "Computers",
        "mobile": "Mobile",
        "media": "Media",
        "iot": "IoT",
        "printer": "3D Printer",
        "unknown": "Unknown",
    }.get(category, "Unknown")


def _category_accent(category: str) -> str:
    return {
        "infrastructure": "cyan",
        "servers": "green",
        "computers": "blue",
        "mobile": "amber",
        "media": "violet",
        "iot": "orange",
        "printer": "rose",
        "unknown": "slate",
    }.get(category, "slate")


def _normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


def _is_locally_administered_mac(value: str) -> bool:
    normalized = _normalize_mac(value)
    if len(normalized) != 12:
        return False
    return bool(int(normalized[:2], 16) & 0x02)


def _inventory_key(item: dict[str, object]) -> str:
    return str(item.get("id") or item.get("ip") or item.get("name") or "")


def _load_existing_inventory(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    items = raw.get("devices", []) if isinstance(raw, dict) else []
    existing: dict[str, dict[str, object]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _inventory_key(item)
        if key:
            existing[key] = item
    return existing


def _load_existing_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _load_scan_state(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_scan_state(path: Path, state: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _host_identity(host: ET.Element) -> str:
    for address in host.findall("address"):
        if address.attrib.get("addrtype") == "ipv4":
            return address.attrib.get("addr", "").strip()
    for address in host.findall("address"):
        if address.attrib.get("addrtype") == "mac":
            return address.attrib.get("addr", "").strip().lower()
    hostnames = [item.attrib.get("name", "").strip() for item in host.findall("hostnames/hostname")]
    return next((name for name in hostnames if name), "")


def _merge_discovery_hosts(discovery_xml: Path, service_xml: Path) -> None:
    if not discovery_xml.exists() or not service_xml.exists():
        return
    try:
        discovery_root = ET.parse(discovery_xml).getroot()
        service_tree = ET.parse(service_xml)
        service_root = service_tree.getroot()
    except (ET.ParseError, OSError):
        return

    known_hosts = {
        identity
        for host in service_root.findall("host")
        if (identity := _host_identity(host))
    }
    appended = False
    for host in discovery_root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        identity = _host_identity(host)
        if not identity or identity in known_hosts:
            continue
        service_root.append(host)
        known_hosts.add(identity)
        appended = True
    if appended:
        service_tree.write(service_xml, encoding="utf-8", xml_declaration=True)


def _update_scan_state(
    path: Path,
    *,
    now: datetime,
    running: bool,
    success: bool | None = None,
    duration_seconds: float | None = None,
    error_summary: str = "",
    pid: int | None = None,
) -> dict[str, object]:
    state = _load_scan_state(path)
    state["scanRunning"] = running
    state["configuredScanMinutes"] = int(state.get("configuredScanMinutes") or 0)
    if running:
        state["lastScanStart"] = now.isoformat()
        state["scanPid"] = pid or os.getpid()
        state["lastErrorSummary"] = ""
    else:
        state["scanPid"] = 0
    if duration_seconds is not None:
        state["lastScanDurationSeconds"] = round(max(duration_seconds, 0.0), 3)
    if success is True:
        state["lastSuccessfulScan"] = now.isoformat()
        state["lastErrorSummary"] = ""
    elif success is False:
        state["lastFailedScan"] = now.isoformat()
        state["lastErrorSummary"] = error_summary[:240]
    _save_scan_state(path, state)
    return state


def _calc_next_expected_scan(state: dict[str, object], interval_minutes: int) -> str:
    baseline = state.get("lastScanStart") or state.get("lastSuccessfulScan")
    if not isinstance(baseline, str) or not baseline.strip():
        return ""
    try:
        dt = datetime.fromisoformat(baseline)
    except ValueError:
        return ""
    if interval_minutes <= 0:
        return dt.replace(microsecond=0).isoformat(timespec="seconds")
    return (dt + timedelta(minutes=interval_minutes)).replace(microsecond=0).isoformat(timespec="seconds")


def _load_overrides(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = raw.get("devices", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    return [item for item in items if isinstance(item, dict)]


def _save_overrides(path: Path, items: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"devices": items}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _find_matching_override(
    overrides: list[dict[str, object]],
    ip: str,
    mac: str,
    hostname: str,
) -> dict[str, object] | None:
    normalized_mac = _normalize_mac(mac)
    lowered_hostname = hostname.strip().lower()
    for override in overrides:
        override_ip = str(override.get("ip") or "").strip()
        if override_ip and override_ip == ip:
            return override
        override_mac = _normalize_mac(str(override.get("mac") or ""))
        if override_mac and override_mac == normalized_mac:
            return override
        override_hostname = str(override.get("hostname") or "").strip().lower()
        if override_hostname and override_hostname == lowered_hostname:
            return override
    return None


def _first_key_value(element: ET.Element | None, *paths: tuple[str, str]) -> str:
    if element is None:
        return ""
    for tag, key in paths:
        found = element.find(f"{tag}[@key='{key}']")
        if found is not None and (found.text or "").strip():
            return (found.text or "").strip()
    return ""


def _iter_script_strings(element: ET.Element) -> list[str]:
    values: list[str] = []
    output = element.attrib.get("output", "").strip()
    if output:
        values.append(output)
    for node in element.iter():
        key = node.attrib.get("key", "").strip()
        text = (node.text or "").strip()
        if key and text:
            values.append(f"{key}: {text}")
        elif key:
            values.append(key)
        elif text:
            values.append(text)
    return values


def _extract_ssl_certificate(script: ET.Element | None) -> dict[str, str]:
    if script is None:
        return {}
    strings = _iter_script_strings(script)
    full_text = " ".join(strings)
    subject_cn = _first_key_value(
        script,
        ("./table[@key='subject']/elem", "commonName"),
        ("./table[@key='subject']/elem", "common name"),
        ("./table[@key='subject']/elem", "CN"),
    )
    issuer_org = _first_key_value(
        script,
        ("./table[@key='issuer']/elem", "organizationName"),
        ("./table[@key='issuer']/elem", "O"),
        ("./table[@key='issuer']/elem", "organization"),
    )
    issuer_cn = _first_key_value(
        script,
        ("./table[@key='issuer']/elem", "commonName"),
        ("./table[@key='issuer']/elem", "CN"),
    )
    valid_from = _first_key_value(
        script,
        ("./table[@key='validity']/elem", "notBefore"),
        ("./table[@key='validity']/elem", "validFrom"),
    )
    valid_until = _first_key_value(
        script,
        ("./table[@key='validity']/elem", "notAfter"),
        ("./table[@key='validity']/elem", "validUntil"),
    )
    if not subject_cn:
        match = re.search(r"Subject:.*?(?:CN|commonName)\s*=\s*([A-Za-z0-9._-]+)", full_text, re.IGNORECASE)
        if match:
            subject_cn = match.group(1)
    if not issuer_org:
        match = re.search(r"Issuer:.*?(?:organizationName|O)\s*=\s*([^,]+?)(?:\s+(?:commonName|CN)\s*=|$)", full_text, re.IGNORECASE)
        if match:
            issuer_org = match.group(1).strip()
    if not issuer_cn:
        match = re.search(r"Issuer:.*?(?:commonName|CN)\s*=\s*([A-Za-z0-9 ._-]+)", full_text, re.IGNORECASE)
        if match:
            issuer_cn = match.group(1).strip()
    return {
        "subjectCommonName": subject_cn,
        "issuerOrganization": issuer_org,
        "issuerCommonName": issuer_cn,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "text": full_text,
    }


def _looks_like_bambu_serial(value: str) -> bool:
    return bool(BBL_SERIAL_RE.fullmatch(value.strip()))


def _parse_port_entry(port: ET.Element) -> dict[str, object]:
    service = port.find("service")
    service_name = service.attrib.get("name", "") if service is not None else ""
    product = service.attrib.get("product", "") if service is not None else ""
    version = service.attrib.get("version", "") if service is not None else ""
    extrainfo = service.attrib.get("extrainfo", "") if service is not None else ""
    tunnel = service.attrib.get("tunnel", "") if service is not None else ""
    scripts = port.findall("script")
    ssl_script = next((item for item in scripts if item.attrib.get("id") == "ssl-cert"), None)
    certificate = _extract_ssl_certificate(ssl_script)
    script_text = " ".join(" ".join(_iter_script_strings(script)) for script in scripts).strip()
    return {
        "port": int(port.attrib.get("portid", "0")),
        "protocol": port.attrib.get("protocol", "tcp"),
        "service": service_name,
        "product": product,
        "version": version,
        "extraInfo": extrainfo,
        "tunnel": tunnel,
        "tlsCertificate": certificate,
        "scriptText": script_text,
    }


def _classify_bambu_device(
    hostname: str,
    vendor: str,
    host_os_text: str,
    port_entries: list[dict[str, object]],
) -> dict[str, object]:
    reasons: list[str] = []
    cert_text_parts: list[str] = []
    cn_values: list[str] = []
    port_numbers = {int(item.get("port") or 0) for item in port_entries}
    has_ftps_990 = False
    has_vsftpd = False
    for entry in port_entries:
        port = int(entry.get("port") or 0)
        service_name = str(entry.get("service") or "")
        product = str(entry.get("product") or "")
        version = str(entry.get("version") or "")
        tunnel = str(entry.get("tunnel") or "")
        cert = entry.get("tlsCertificate") if isinstance(entry.get("tlsCertificate"), dict) else {}
        cert_text = " ".join(
            value
            for value in (
                str(cert.get("issuerOrganization") or ""),
                str(cert.get("issuerCommonName") or ""),
                str(cert.get("subjectCommonName") or ""),
                str(cert.get("text") or ""),
            )
            if value
        )
        if cert_text:
            cert_text_parts.append(cert_text)
        subject_cn = str(cert.get("subjectCommonName") or "").strip()
        if subject_cn:
            cn_values.append(subject_cn)
        if port == 990 and (service_name.lower() in {"ssl/ftp", "ftps", "ftp"} or tunnel.lower() == "ssl"):
            has_ftps_990 = True
        if product.lower() == "vsftpd" and version == "3.0.5":
            has_vsftpd = True

    cert_text_all = " ".join(cert_text_parts).lower()
    matching_issuer = next((marker for marker in BBL_ISSUER_MARKERS if marker in cert_text_all), "")
    has_printer_marker = "printer" in cert_text_all
    hostname_mentions_bambu = "bambu" in hostname.lower()
    if matching_issuer:
        reasons.append(f"TLS issuer contains {matching_issuer}")
    if has_printer_marker:
        reasons.append("TLS certificate text contains Printer")
    if has_ftps_990:
        reasons.append("Implicit FTPS detected on TCP 990")
    if has_vsftpd:
        reasons.append("FTP service reports vsftpd 3.0.5")
    if 3000 in port_numbers and 6000 in port_numbers:
        reasons.append("Bambu service-port pattern detected")
    if host_os_text and any(token in host_os_text.lower() for token in ("linux", "unix", "embedded")):
        reasons.append("Embedded Linux or Unix OS fingerprint detected")

    device_id = next((value for value in cn_values if _looks_like_bambu_serial(value)), "")
    if not device_id:
        text_serial = re.search(r"\b([0-9A-Z]{10,})\b", cert_text_all.upper())
        if text_serial:
            candidate = text_serial.group(1)
            if _looks_like_bambu_serial(candidate):
                device_id = candidate
    if device_id:
        reasons.append("Certificate CN resembles a Bambu device ID")
    if hostname_mentions_bambu:
        reasons.append("Hostname mentions Bambu")

    score = 0
    if matching_issuer:
        score += 100
    if has_printer_marker:
        score += 35
    if has_ftps_990:
        score += 25
    if has_vsftpd:
        score += 20
    if 3000 in port_numbers and 6000 in port_numbers:
        score += 25
    if device_id:
        score += 20
    if hostname_mentions_bambu:
        score += 15
    if host_os_text and any(token in host_os_text.lower() for token in ("linux", "unix", "embedded")):
        score += 10

    confirmed = bool(matching_issuer or (has_printer_marker and has_ftps_990 and (device_id or has_vsftpd)))
    probable = not confirmed and has_ftps_990 and 3000 in port_numbers and 6000 in port_numbers and score >= 70
    if not confirmed and not probable:
        return {}

    return {
        "name": "Bambu Lab 3D Printer" if confirmed else "Possible Bambu Lab 3D Printer",
        "category": "printer",
        "categoryLabel": _category_label("printer"),
        "accent": _category_accent("printer"),
        "vendor": vendor if vendor and "bambu" in vendor.lower() else "Bambu Lab",
        "manufacturer": "Bambu Lab",
        "deviceType": "3d_printer",
        "identificationConfidence": "confirmed" if confirmed else "probable",
        "identificationScore": 100 if confirmed else min(score, 89),
        "identificationReasons": reasons,
        "deviceId": device_id,
        "displayEvidence": (
            "Verified by Bambu device certificate"
            if confirmed
            else "FTPS 990 · control services 3000/6000"
        ),
    }


def _merge_devices_by_hardware_id(devices: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    passthrough: list[dict[str, object]] = []
    for device in devices:
        device_id = str(device.get("deviceId") or "").strip()
        if device_id and str(device.get("manufacturer") or "").strip().lower() == "bambu lab":
            grouped.setdefault(f"device-id:{device_id}", []).append(device)
        else:
            passthrough.append(device)

    merged: list[dict[str, object]] = list(passthrough)
    for group in grouped.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        primary = dict(group[0])
        ports_by_key: dict[tuple[int, str], dict[str, object]] = {}
        services: set[str] = set()
        open_ports: set[int] = set()
        interfaces: list[dict[str, str]] = []
        raw_records: list[dict[str, object]] = []
        ips: list[str] = []
        for device in group:
            ip = str(device.get("ip") or "")
            if ip and ip not in ips:
                ips.append(ip)
            interfaces.append(
                {
                    "ip": ip,
                    "mac": str(device.get("mac") or ""),
                    "hostname": str(device.get("hostname") or ""),
                }
            )
            raw_records.append(
                {
                    "id": str(device.get("id") or ""),
                    "ip": ip,
                    "mac": str(device.get("mac") or ""),
                    "hostname": str(device.get("hostname") or ""),
                    "ports": device.get("ports") if isinstance(device.get("ports"), list) else [],
                }
            )
            for port in device.get("ports", []) if isinstance(device.get("ports"), list) else []:
                if not isinstance(port, dict):
                    continue
                key = (int(port.get("port") or 0), str(port.get("protocol") or "tcp"))
                ports_by_key[key] = port
            for service in device.get("services", []) if isinstance(device.get("services"), list) else []:
                services.add(str(service))
            for port in device.get("openPorts", []) if isinstance(device.get("openPorts"), list) else []:
                open_ports.add(int(port))
        primary["ips"] = ips
        primary["interfaces"] = interfaces
        primary["rawRecords"] = raw_records
        primary["ip"] = ips[0] if ips else str(primary.get("ip") or "")
        primary["ports"] = sorted(ports_by_key.values(), key=lambda item: (int(item.get("port") or 0), str(item.get("protocol") or "")))
        primary["openPorts"] = sorted(open_ports)
        primary["services"] = sorted(services)
        primary["portCount"] = len(primary["ports"])
        merged.append(primary)
    return sorted(merged, key=lambda item: (str(item.get("category") or ""), str(item.get("name") or ""), str(item.get("ip") or "")))


def _apply_override(device: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    updated = dict(device)
    if "name" in override and str(override.get("name") or "").strip():
        updated["name"] = str(override.get("name")).strip()
    if "hostname" in override and str(override.get("hostname") or "").strip():
        updated["hostname"] = str(override.get("hostname")).strip()
    if "category" in override:
        category = str(override.get("category") or "").strip().lower()
        if category in VALID_CATEGORIES:
            updated["category"] = category
            updated["categoryLabel"] = _category_label(category)
            updated["accent"] = _category_accent(category)
    return updated


def _append_change_events(config: AppConfig, now: datetime, previous: dict[str, dict[str, object]], current: list[dict[str, object]]) -> None:
    current_map = {_inventory_key(item): item for item in current}
    events = _load_existing_events(Path(config.nmap_events_json))
    new_events: list[dict[str, object]] = []

    for device_id, device in current_map.items():
        if not device_id:
            continue
        old = previous.get(device_id)
        if old is None:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "new_host",
                    "severity": "warning",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"New host discovered: {device.get('name') or device.get('hostname') or device_id}",
                }
            )
            continue
        old_ports = {int(port) for port in old.get("openPorts", []) if isinstance(port, int)}
        current_ports = {int(port) for port in device.get("openPorts", []) if isinstance(port, int)}
        opened = sorted(current_ports - old_ports)
        closed = sorted(old_ports - current_ports)
        old_name = str(old.get("name") or "")
        current_name = str(device.get("name") or "")
        if old_name and current_name and old_name != current_name:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "device_renamed",
                    "severity": "info",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"Device renamed: {old_name} -> {current_name}",
                }
            )
        old_category = str(old.get("category") or "")
        current_category = str(device.get("category") or "")
        if old_category and current_category and old_category != current_category:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "device_reclassified",
                    "severity": "info",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"Category changed: {current_name or device_id} -> {current_category}",
                }
            )
        if opened:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "port_opened",
                    "severity": "warning",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"Opened port(s): {', '.join(str(port) for port in opened)} on {device.get('name') or device_id}",
                }
            )
        if closed:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "port_closed",
                    "severity": "info",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"Closed port(s): {', '.join(str(port) for port in closed)} on {device.get('name') or device_id}",
                }
            )

    for device_id, device in previous.items():
        if device_id and device_id not in current_map:
            new_events.append(
                {
                    "timestamp": now.isoformat(),
                    "event_type": "host_missing",
                    "severity": "warning",
                    "source": str(device.get("ip") or device.get("hostname") or "nmap"),
                    "message": f"Host missing from latest scan: {device.get('name') or device.get('hostname') or device_id}",
                }
            )

    if not new_events:
        return

    merged = sorted(events + new_events, key=lambda item: str(item.get("timestamp") or ""))[-200:]
    events_path = Path(config.nmap_events_json)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.write_text(json.dumps({"events": merged}, indent=2), encoding="utf-8")


def export_nmap_inventory_json(config: AppConfig, now: datetime) -> tuple[bool, str]:
    xml_path = Path(config.nmap_inventory_xml)
    json_path = Path(config.nmap_inventory_json)
    overrides = _load_overrides(Path(config.nmap_overrides_json))
    scan_state_path = Path(config.nmap_state_json)
    if not xml_path.exists():
        return False, f"Nmap XML not found: {xml_path}"

    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as exc:
        return False, f"Nmap XML parse failed: {exc}"

    args = root.attrib.get("args", "")
    network = ""
    for token in reversed(args.split()):
        if "/" in token or token.count(".") == 3:
            network = token
            break

    devices: list[dict[str, object]] = []
    raw_devices: list[dict[str, object]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for address in host.findall("address"):
            addrtype = address.attrib.get("addrtype", "")
            if addrtype == "ipv4":
                ip = address.attrib.get("addr", "")
            elif addrtype == "mac":
                mac = address.attrib.get("addr", "")
                vendor = address.attrib.get("vendor", "")

        hostnames = [item.attrib.get("name", "").strip() for item in host.findall("hostnames/hostname") if item.attrib.get("name", "").strip()]
        hostname = hostnames[0] if hostnames else ip or "unknown-device"
        os_fragments = [
            item.attrib.get("name", "").strip()
            for item in host.findall("os/osmatch")
            if item.attrib.get("name", "").strip()
        ]
        os_fragments.extend(
            " ".join(
                value
                for value in (
                    item.attrib.get("vendor", "").strip(),
                    item.attrib.get("osfamily", "").strip(),
                    item.attrib.get("type", "").strip(),
                )
                if value
            )
            for item in host.findall("os/osclass")
        )
        host_os_text = " ".join(fragment for fragment in os_fragments if fragment).strip()

        port_entries: list[dict[str, object]] = []
        open_ports: list[int] = []
        services: list[str] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            entry = _parse_port_entry(port)
            port_id = int(entry.get("port") or 0)
            service_name = str(entry.get("service") or "")
            port_entries.append(entry)
            open_ports.append(port_id)
            if service_name:
                services.append(service_name)

        category, generic_score, generic_reasons = _rank_category_signals(hostname, vendor, host_os_text, ip, port_entries)
        label_name = hostname if hostname and hostname != ip else vendor or ip
        assessment_text = " ".join(
            part
            for part in (
                hostname,
                vendor,
                host_os_text,
                " ".join(services),
                " ".join(str(item.get("scriptText") or "") for item in port_entries if str(item.get("scriptText") or "").strip()),
            )
            if part
        ).lower()
        device = {
            "id": ip or hostname,
            "name": _friendly_name_from_signals(hostname, vendor, category, assessment_text, label_name),
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "status": "up",
            "category": category,
            "categoryLabel": _category_label(category),
            "accent": _category_accent(category),
            "ports": port_entries,
            "openPorts": open_ports,
            "services": sorted(set(services)),
            "portCount": len(port_entries),
            "lastSeen": now.isoformat(),
            "manufacturer": vendor,
            "deviceType": category,
            "identificationConfidence": "probable" if generic_score >= 70 else "guessed" if generic_score >= 30 else "unknown",
            "identificationScore": generic_score,
            "identificationReasons": generic_reasons,
            "deviceId": "",
            "ips": [ip] if ip else [],
            "interfaces": [{"ip": ip, "mac": mac, "hostname": hostname}] if ip or mac or hostname else [],
            "osFingerprint": host_os_text,
            "rawRecords": [],
            "displayEvidence": _summarize_reasons(generic_reasons),
        }
        bambu = _classify_bambu_device(hostname, vendor, host_os_text, port_entries)
        if bambu:
            device.update(bambu)
        elif category == "unknown":
            device["identificationConfidence"] = "unknown"
        raw_devices.append(dict(device))
        override = _find_matching_override(overrides, ip, mac, hostname)
        if override and bool(override.get("hidden")):
            continue
        if override:
            device = _apply_override(device, override)
        devices.append(device)

    previous = _load_existing_inventory(json_path)
    sorted_devices = _merge_devices_by_hardware_id(devices)
    scan_state = _load_scan_state(scan_state_path)
    interval_minutes = max(5, int(config.nmap_scan_minutes))
    scan_state["configuredScanMinutes"] = interval_minutes
    next_expected_scan = _calc_next_expected_scan(scan_state, interval_minutes)
    payload = {
        "scannedAt": now.isoformat(),
        "network": network,
        "sourceXml": str(xml_path),
        "deviceCount": len(sorted_devices),
        "rawDeviceCount": len(raw_devices),
        "rawDevices": raw_devices,
        "scanState": {
            "lastScanStart": str(scan_state.get("lastScanStart") or ""),
            "lastSuccessfulScan": str(scan_state.get("lastSuccessfulScan") or ""),
            "lastFailedScan": str(scan_state.get("lastFailedScan") or ""),
            "lastScanDurationSeconds": float(scan_state.get("lastScanDurationSeconds") or 0.0),
            "nextExpectedScan": next_expected_scan,
            "configuredScanMinutes": interval_minutes,
            "scanRunning": bool(scan_state.get("scanRunning")),
            "lastErrorSummary": str(scan_state.get("lastErrorSummary") or ""),
        },
        "devices": sorted_devices,
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _append_change_events(config, now, previous, sorted_devices)
    return True, f"Nmap inventory JSON written to {json_path}"


def list_nmap_devices(config: AppConfig) -> str:
    inventory_path = Path(config.nmap_inventory_json)
    if not inventory_path.exists():
        return "No Nmap inventory JSON found. Run `pi-probe-discord nmap-scan` first."
    try:
        payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"Could not read Nmap inventory JSON: {exc}"
    items = payload.get("devices", []) if isinstance(payload, dict) else []
    if not isinstance(items, list) or not items:
        return "No devices found in the latest Nmap inventory."
    lines = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "?")
        mac = str(item.get("mac") or "-")
        category = str(item.get("category") or "unknown")
        name = shorten(str(item.get("name") or item.get("hostname") or ip), width=30, placeholder="...")
        vendor = shorten(str(item.get("vendor") or "-"), width=24, placeholder="...")
        lines.append(f"{ip:15}  {mac:17}  {category:14}  {name:30}  {vendor}")
    header = f"{'IP':15}  {'MAC':17}  {'CATEGORY':14}  {'NAME':30}  VENDOR"
    return "\n".join([header, "-" * len(header), *lines])


def upsert_nmap_override(
    config: AppConfig,
    *,
    ip: str = "",
    mac: str = "",
    hostname: str = "",
    name: str = "",
    category: str = "",
    hidden: bool | None = None,
) -> str:
    selectors = [("ip", ip.strip()), ("mac", mac.strip()), ("hostname", hostname.strip())]
    active_selectors = [(key, value) for key, value in selectors if value]
    if len(active_selectors) != 1:
        raise RuntimeError("Specify exactly one selector: --ip, --mac, or --hostname.")
    if not name.strip() and not category.strip() and hidden is None:
        raise RuntimeError("Provide at least one change: --name, --category, or --hidden.")
    if category.strip() and category.strip().lower() not in VALID_CATEGORIES:
        raise RuntimeError(f"Invalid category: {category}. Valid values: {', '.join(sorted(VALID_CATEGORIES))}")

    key, value = active_selectors[0]
    overrides_path = Path(config.nmap_overrides_json)
    overrides = _load_overrides(overrides_path)
    existing = _find_matching_override(
        overrides,
        ip if key == "ip" else "",
        mac if key == "mac" else "",
        hostname if key == "hostname" else "",
    )
    if existing is None:
        existing = {key: value}
        overrides.append(existing)
    else:
        existing.clear()
        existing[key] = value
    if name.strip():
        existing["name"] = name.strip()
    if category.strip():
        existing["category"] = category.strip().lower()
    if hidden is not None:
        existing["hidden"] = hidden
    _save_overrides(overrides_path, overrides)
    return f"Saved Nmap override for {key}={value} in {overrides_path}"


def remove_nmap_override(config: AppConfig, *, ip: str = "", mac: str = "", hostname: str = "") -> str:
    selectors = [("ip", ip.strip()), ("mac", mac.strip()), ("hostname", hostname.strip())]
    active_selectors = [(key, value) for key, value in selectors if value]
    if len(active_selectors) != 1:
        raise RuntimeError("Specify exactly one selector: --ip, --mac, or --hostname.")
    key, value = active_selectors[0]
    overrides_path = Path(config.nmap_overrides_json)
    overrides = _load_overrides(overrides_path)
    kept = [item for item in overrides if str(item.get(key) or "").strip() != value]
    if len(kept) == len(overrides):
        return f"No Nmap override found for {key}={value}"
    _save_overrides(overrides_path, kept)
    return f"Removed Nmap override for {key}={value}"


def run_nmap_inventory_scan(config: AppConfig, now: datetime) -> tuple[bool, str]:
    xml_path = Path(config.nmap_inventory_xml)
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    discovery_xml_path = xml_path.with_name(f"{xml_path.stem}.discovery.xml")
    state_path = Path(config.nmap_state_json)
    lock_path = state_path.with_suffix(".lock")
    nmap_args = shlex.split(config.nmap_arguments)
    legacy_fast_scan = shlex.split("-F --min-rate 2000 --host-timeout 30s")
    if nmap_args == legacy_fast_scan:
        nmap_args = shlex.split("-Pn --top-ports 200 --min-rate 2000 --host-timeout 30s")
    if "-F" in nmap_args and "-Pn" not in nmap_args:
        nmap_args.append("-Pn")
    if "-sV" not in nmap_args and "--version-all" not in nmap_args and "--version-light" not in nmap_args:
        nmap_args.extend(["-sV", "--version-light"])
    if "--script" not in nmap_args:
        nmap_args.extend(["--script", "ssl-cert"])
    if "--script-timeout" not in nmap_args:
        nmap_args.extend(["--script-timeout", "20s"])
    discovery_args = ["nmap", "-sn", "-PR", config.nmap_targets, "-oX", str(discovery_xml_path)]
    args = ["nmap", *nmap_args, config.nmap_targets, "-oX", str(xml_path)]
    print(f"Running nmap discovery scan: {' '.join(discovery_args)}", file=sys.stderr, flush=True)
    print(f"Running nmap inventory scan: {' '.join(args)}", file=sys.stderr, flush=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False, "Nmap scan already running"
        started_monotonic = time.monotonic()
        _update_scan_state(
            state_path,
            now=now,
            running=True,
            pid=os.getpid(),
        )
        try:
            try:
                discovery_process = subprocess.Popen(
                    discovery_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except FileNotFoundError:
                _update_scan_state(
                    state_path,
                    now=datetime.now().astimezone(),
                    running=False,
                    success=False,
                    duration_seconds=time.monotonic() - started_monotonic,
                    error_summary="nmap is not installed",
                )
                return False, "nmap is not installed"
            discovery_output: list[str] = []
            try:
                assert discovery_process.stdout is not None
                for line in discovery_process.stdout:
                    text = line.rstrip()
                    discovery_output.append(text)
                    if (
                        text.startswith("Starting Nmap")
                        or text.startswith("Nmap scan report for ")
                        or text.startswith("Host is up")
                        or text.startswith("MAC Address:")
                        or text.startswith("Nmap done:")
                    ):
                        print(text, file=sys.stderr, flush=True)
                discovery_code = discovery_process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                discovery_process.kill()
                discovery_process.wait(timeout=5)
                discovery_code = 124
            if discovery_code != 0:
                discovery_error = next((line for line in reversed(discovery_output) if line.strip()), f"nmap discovery exited with {discovery_code}")
                print(f"Discovery scan warning: {discovery_error}", file=sys.stderr, flush=True)
            output_lines: list[str] = []
            host_down_count = 0
            scan_report_count = 0
            try:
                assert process.stdout is not None
                for line in process.stdout:
                    text = line.rstrip()
                    output_lines.append(text)
                    if "[host down]" in text:
                        host_down_count += 1
                        continue
                    if text.startswith("Nmap scan report for "):
                        scan_report_count += 1
                        if scan_report_count > 1:
                            print("", file=sys.stderr, flush=True)
                    if (
                        text.startswith("Discovered open port ")
                        or text.startswith("Stats: ")
                        or "Timing:" in text
                        or text.startswith("Completed ")
                        or text.startswith("Initiating ")
                        or text.startswith("Nmap scan report for ")
                        or text.startswith("PORT")
                        or text.startswith("Host is up")
                        or text.startswith("Not shown:")
                        or text.startswith("All 100 scanned ports")
                        or text.startswith("MAC Address:")
                        or text.startswith("Nmap done:")
                        or text.startswith("Raw packets sent:")
                        or text.startswith("Starting Nmap")
                    ):
                        print(text, file=sys.stderr, flush=True)
                return_code = process.wait(timeout=900)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                duration = time.monotonic() - started_monotonic
                _update_scan_state(
                    state_path,
                    now=datetime.now().astimezone(),
                    running=False,
                    success=False,
                    duration_seconds=duration,
                    error_summary="nmap scan timed out",
                )
                return False, "nmap scan timed out"
            if host_down_count:
                print(f"Suppressed {host_down_count} host-down lines.", file=sys.stderr, flush=True)
            if return_code != 0:
                stderr = next((line for line in reversed(output_lines) if line.strip()), f"nmap exited with {return_code}")
                duration = time.monotonic() - started_monotonic
                _update_scan_state(
                    state_path,
                    now=datetime.now().astimezone(),
                    running=False,
                    success=False,
                    duration_seconds=duration,
                    error_summary=stderr,
                )
                return False, f"Nmap scan failed: {stderr}"

            _merge_discovery_hosts(discovery_xml_path, xml_path)
            completed_at = datetime.now().astimezone()
            duration = time.monotonic() - started_monotonic
            _update_scan_state(
                state_path,
                now=completed_at,
                running=False,
                success=True,
                duration_seconds=duration,
            )
            ok, message = export_nmap_inventory_json(config, completed_at)
            if not ok:
                _update_scan_state(
                    state_path,
                    now=completed_at,
                    running=False,
                    success=False,
                    duration_seconds=duration,
                    error_summary=message,
                )
                return False, message
            return True, f"Completed nmap scan for {config.nmap_targets}; {message}"
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
