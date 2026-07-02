from __future__ import annotations

import json
import shlex
import subprocess
import sys
import re
from datetime import datetime
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
    "unknown",
}


def _first_text(element: ET.Element | None, xpath: str, default: str = "") -> str:
    if element is None:
        return default
    found = element.find(xpath)
    if found is None:
        return default
    return (found.text or "").strip()


def _guess_category(hostname: str, vendor: str, open_ports: list[int], services: list[str], ip: str) -> str:
    text = f"{hostname} {vendor} {' '.join(services)}".lower()
    if ip.endswith(".1") or any(token in text for token in ("router", "gateway", "tp-link", "archer", "ubiquiti")):
        return "infrastructure"
    if any(port in open_ports for port in (53, 67, 68, 80, 443, 22)) and any(
        token in text for token in ("pi", "raspberry", "server", "nas", "pihole", "proxmox")
    ):
        return "servers"
    if any(token in text for token in ("iphone", "pixel", "android", "phone", "samsung")):
        return "mobile"
    if any(token in text for token in ("tv", "chromecast", "roku", "apple tv", "fire tv", "playstation", "xbox")):
        return "media"
    if any(port in open_ports for port in (9100, 515, 631, 554, 8008, 8009, 8080)) or any(
        token in text for token in ("printer", "camera", "plug", "switch", "echo", "ring", "vacuum", "iot")
    ):
        return "iot"
    if any(token in text for token in ("laptop", "desktop", "pc", "lenovo", "thinkpad", "yoga", "macbook", "workstation")):
        return "computers"
    return "unknown"


def _category_label(category: str) -> str:
    return {
        "infrastructure": "Infrastructure",
        "servers": "Servers",
        "computers": "Computers",
        "mobile": "Mobile",
        "media": "Media",
        "iot": "IoT",
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
        "unknown": "slate",
    }.get(category, "slate")


def _normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


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

        port_entries: list[dict[str, object]] = []
        open_ports: list[int] = []
        services: list[str] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            port_id = int(port.attrib.get("portid", "0"))
            service_name = port.find("service").attrib.get("name", "") if port.find("service") is not None else ""
            product = port.find("service").attrib.get("product", "") if port.find("service") is not None else ""
            version = port.find("service").attrib.get("version", "") if port.find("service") is not None else ""
            entry = {
                "port": port_id,
                "protocol": port.attrib.get("protocol", "tcp"),
                "service": service_name,
                "product": product,
                "version": version,
            }
            port_entries.append(entry)
            open_ports.append(port_id)
            if service_name:
                services.append(service_name)

        category = _guess_category(hostname, vendor, open_ports, services, ip)
        label_name = hostname if hostname and hostname != ip else vendor or ip
        device = {
            "id": ip or hostname,
            "name": label_name,
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
        }
        override = _find_matching_override(overrides, ip, mac, hostname)
        if override and bool(override.get("hidden")):
            continue
        if override:
            device = _apply_override(device, override)
        devices.append(device)

    previous = _load_existing_inventory(json_path)
    sorted_devices = sorted(devices, key=lambda item: (item["category"], item["name"], item["ip"]))
    payload = {
        "scannedAt": now.isoformat(),
        "network": network,
        "sourceXml": str(xml_path),
        "deviceCount": len(sorted_devices),
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
    nmap_args = shlex.split(config.nmap_arguments)
    args = ["nmap", *nmap_args, config.nmap_targets, "-oX", str(xml_path)]
    print(f"Running nmap inventory scan: {' '.join(args)}", file=sys.stderr, flush=True)
    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        return False, "nmap is not installed"
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
        return False, "nmap scan timed out"
    if host_down_count:
        print(f"Suppressed {host_down_count} host-down lines.", file=sys.stderr, flush=True)
    if return_code != 0:
        stderr = next((line for line in reversed(output_lines) if line.strip()), f"nmap exited with {return_code}")
        return False, f"Nmap scan failed: {stderr}"

    ok, message = export_nmap_inventory_json(config, now)
    if not ok:
        return False, message
    return True, f"Completed nmap scan for {config.nmap_targets}; {message}"
