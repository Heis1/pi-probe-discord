from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import AppConfig


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
        key = str(item.get("id") or item.get("ip") or item.get("name") or "")
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


def _append_change_events(config: AppConfig, now: datetime, previous: dict[str, dict[str, object]], current: list[dict[str, object]]) -> None:
    current_map = {str(item.get("id") or item.get("ip") or item.get("name") or ""): item for item in current}
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
        devices.append(
            {
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
        )

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
