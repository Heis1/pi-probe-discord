from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import AppConfig
from .router_webui import collect_router_webui_snapshot


_DOT1D_BASEPORT_IFINDEX_OID = ".1.3.6.1.2.1.17.1.4.1.2"
_IF_NAME_OID = ".1.3.6.1.2.1.31.1.1.1.1"
_IF_DESCR_OID = ".1.3.6.1.2.1.2.2.1.2"
_IF_PHYSADDRESS_OID = ".1.3.6.1.2.1.2.2.1.6"
_DOT1D_TP_FDB_PORT_OID = ".1.3.6.1.2.1.17.4.3.1.2"
_DOT1Q_TP_FDB_PORT_OID = ".1.3.6.1.2.1.17.7.1.2.2.1.2"

_OID_VALUE_RE = re.compile(r"^\s*([^=]+?)\s*=\s*([^:]+):\s*(.+?)\s*$")
_BASEPORT_RE = re.compile(r"(?:dot1dBasePortIfIndex|%s)\.(\d+)$" % re.escape(_DOT1D_BASEPORT_IFINDEX_OID))
_IFNAME_RE = re.compile(r"(?:ifName|%s)\.(\d+)$" % re.escape(_IF_NAME_OID))
_IFDESCR_RE = re.compile(r"(?:ifDescr|%s)\.(\d+)$" % re.escape(_IF_DESCR_OID))
_IFPHYS_RE = re.compile(r"(?:ifPhysAddress|%s)\.(\d+)$" % re.escape(_IF_PHYSADDRESS_OID))
_FDB_RE = re.compile(r"(?:dot1dTpFdbPort|%s)\.((?:\d+\.){5}\d+)$" % re.escape(_DOT1D_TP_FDB_PORT_OID))
_QFDB_RE = re.compile(r"(?:dot1qTpFdbPort|%s)\.\d+\.((?:\d+\.){5}\d+)$" % re.escape(_DOT1Q_TP_FDB_PORT_OID))
_HEX_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def _normalize_mac(value: str) -> str:
    return ":".join(
        value.lower().replace("-", ":").replace(".", ":").split(":")
    ).replace("::", ":").strip(":")


def _compact_mac(value: str) -> str:
    normalized = re.sub(r"[^0-9a-f]", "", value.lower())
    if len(normalized) != 12:
        return ""
    return ":".join(normalized[idx : idx + 2] for idx in range(0, 12, 2))


def _mac_from_oid_suffix(value: str) -> str:
    parts = [part for part in value.split(".") if part.isdigit()]
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(part):02x}" for part in parts)
    except ValueError:
        return ""


def _mac_from_value(value: str) -> str:
    match = _HEX_MAC_RE.search(value)
    if match:
        return _compact_mac(match.group(1))
    hex_bytes = [part for part in re.split(r"[\s:]+", value.strip()) if part]
    if len(hex_bytes) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{2}", part) for part in hex_bytes):
        return ":".join(part.lower() for part in hex_bytes)
    return ""


def _clean_string(value: str) -> str:
    cleaned = value.strip().strip('"')
    return " ".join(cleaned.split())


def _snmpwalk_args(config: AppConfig, node: dict[str, Any], oid: str) -> list[str]:
    version = str(node.get("version") or "2c").strip()
    community = str(node.get("community") or "").strip()
    host = str(node.get("host") or node.get("management_ip") or "").strip()
    return [
        config.topology_snmpwalk_bin,
        f"-v{version}",
        "-c",
        community,
        "-t",
        str(config.topology_snmp_timeout_seconds),
        "-r",
        "1",
        host,
        oid,
    ]


def _run_snmpwalk(config: AppConfig, node: dict[str, Any], oid: str) -> tuple[bool, list[str], str]:
    command = _snmpwalk_args(config, node, oid)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=config.topology_snmp_timeout_seconds + 2, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, [], str(exc)
    output = completed.stdout or ""
    error = (completed.stderr or "").strip()
    if completed.returncode != 0:
        return False, output.splitlines(), error or f"snmpwalk exited with {completed.returncode}"
    return True, output.splitlines(), ""


def _parse_snmpwalk_lines(lines: list[str]) -> dict[str, Any]:
    baseport_ifindex: dict[int, int] = {}
    if_names: dict[int, str] = {}
    if_descrs: dict[int, str] = {}
    if_macs: dict[int, str] = {}
    fdb: dict[str, int] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or " = " not in line:
            continue
        match = _OID_VALUE_RE.match(line)
        if not match:
            continue
        oid, _, value = match.groups()
        value = _clean_string(value)
        base_match = _BASEPORT_RE.search(oid)
        if base_match and value.isdigit():
            baseport_ifindex[int(base_match.group(1))] = int(value)
            continue
        name_match = _IFNAME_RE.search(oid)
        if name_match:
            if_names[int(name_match.group(1))] = value
            continue
        descr_match = _IFDESCR_RE.search(oid)
        if descr_match:
            if_descrs[int(descr_match.group(1))] = value
            continue
        phys_match = _IFPHYS_RE.search(oid)
        if phys_match:
            mac = _mac_from_value(value)
            if mac:
                if_macs[int(phys_match.group(1))] = mac
            continue
        fdb_match = _FDB_RE.search(oid) or _QFDB_RE.search(oid)
        if fdb_match and value.isdigit():
            mac = _mac_from_oid_suffix(fdb_match.group(1))
            if mac:
                fdb[mac] = int(value)
    interfaces: list[dict[str, Any]] = []
    for ifindex in sorted(set(baseport_ifindex.values()) | set(if_names) | set(if_descrs) | set(if_macs)):
        interfaces.append(
            {
                "ifIndex": ifindex,
                "name": if_names.get(ifindex, ""),
                "description": if_descrs.get(ifindex, ""),
                "mac": if_macs.get(ifindex, ""),
            }
        )
    baseports: dict[int, dict[str, Any]] = {}
    for base_port, ifindex in baseport_ifindex.items():
        info = next((item for item in interfaces if int(item.get("ifIndex") or 0) == ifindex), None)
        baseports[base_port] = {
            "basePort": base_port,
            "ifIndex": ifindex,
            "name": str(info.get("name") or "") if info else "",
            "description": str(info.get("description") or "") if info else "",
            "mac": str(info.get("mac") or "") if info else "",
        }
    return {
        "interfaces": interfaces,
        "basePorts": list(baseports.values()),
        "fdb": [
            {
                "mac": mac,
                "basePort": base_port,
                "ifIndex": int(baseports.get(base_port, {}).get("ifIndex") or 0),
                "interfaceName": str(baseports.get(base_port, {}).get("name") or ""),
                "interfaceDescription": str(baseports.get(base_port, {}).get("description") or ""),
            }
            for mac, base_port in sorted(fdb.items())
        ],
    }


def _load_topology_nodes(config: AppConfig) -> list[dict[str, Any]]:
    raw = config.topology_nodes_json.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    nodes: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or item.get("management_ip") or "").strip()
        community = str(item.get("community") or "").strip()
        if not host or not community:
            continue
        node_id = str(item.get("id") or item.get("name") or host).strip()
        nodes.append(
            {
                "id": node_id,
                "name": str(item.get("name") or host).strip(),
                "host": host,
                "managementIp": str(item.get("management_ip") or host).strip(),
                "community": community,
                "version": str(item.get("version") or "2c").strip(),
                "role": str(item.get("role") or "").strip().lower(),
                "location": str(item.get("location") or "").strip(),
            }
        )
    return nodes


def _node_rank(node: dict[str, Any]) -> tuple[int, int]:
    role = str(node.get("role") or "")
    depth = int(node.get("depth") or 0)
    rank = {
        "extender": 100,
        "access_point": 95,
        "mesh": 95,
        "switch": 80,
        "bridge": 80,
        "router": 40,
    }.get(role, 50)
    return rank, depth


def _resolve_node_relationships(snapshot: dict[str, Any]) -> None:
    nodes = snapshot.get("nodes", [])
    if not isinstance(nodes, list):
        return
    node_by_id = {str(node.get("id") or ""): node for node in nodes}
    node_macs: dict[str, set[str]] = {
        str(node.get("id") or ""): {
            _compact_mac(str(interface.get("mac") or ""))
            for interface in node.get("interfaces", [])
            if isinstance(interface, dict) and _compact_mac(str(interface.get("mac") or ""))
        }
        for node in nodes
    }
    for node in nodes:
        node["parentNodeId"] = ""
        node["parentManagementIp"] = ""
        node["parentName"] = ""
        node["depth"] = 0
    for node in nodes:
        current_id = str(node.get("id") or "")
        macs = node_macs.get(current_id, set())
        candidates: list[dict[str, Any]] = []
        if not macs:
            continue
        for other in nodes:
            other_id = str(other.get("id") or "")
            if other_id == current_id:
                continue
            fdb_entries = other.get("fdb", [])
            if not isinstance(fdb_entries, list):
                continue
            learned = {
                _compact_mac(str(entry.get("mac") or ""))
                for entry in fdb_entries
                if isinstance(entry, dict)
            }
            if learned.intersection(macs):
                candidates.append(other)
        if not candidates:
            continue
        parent = sorted(candidates, key=lambda item: (_node_rank(item)[0], str(item.get("name") or "")), reverse=True)[0]
        node["parentNodeId"] = str(parent.get("id") or "")
        node["parentManagementIp"] = str(parent.get("managementIp") or "")
        node["parentName"] = str(parent.get("name") or "")
    changed = True
    while changed:
        changed = False
        for node in nodes:
            parent_id = str(node.get("parentNodeId") or "")
            parent = node_by_id.get(parent_id)
            depth = int(parent.get("depth") or 0) + 1 if parent is not None else 0
            if depth != int(node.get("depth") or 0):
                node["depth"] = depth
                changed = True


def _merge_router_webui_snapshot(snapshot: dict[str, Any], router_snapshot: dict[str, Any]) -> dict[str, Any]:
    host_table = router_snapshot.get("hostTable", [])
    if not isinstance(host_table, list):
        host_table = []
    snapshot["hostTable"] = host_table
    router_nodes = router_snapshot.get("nodes", [])
    if not isinstance(router_nodes, list):
        router_nodes = []
    existing_nodes = snapshot.get("nodes", [])
    if not isinstance(existing_nodes, list):
        existing_nodes = []
    node_by_ip = {
        str(node.get("managementIp") or ""): node
        for node in existing_nodes
        if isinstance(node, dict)
    }
    for router_node in router_nodes:
        if not isinstance(router_node, dict):
            continue
        router_ip = str(router_node.get("managementIp") or "")
        existing = node_by_ip.get(router_ip)
        if existing is None:
            existing_nodes.append(router_node)
            node_by_ip[router_ip] = router_node
            continue
        if not existing.get("name"):
            existing["name"] = router_node.get("name", "")
        existing["webUiHostCount"] = int(router_node.get("webUiHostCount") or 0)
        if not existing.get("ok"):
            existing["ok"] = bool(router_node.get("ok"))
        existing.setdefault("errors", [])
    snapshot["nodes"] = existing_nodes
    for key in ("notes", "errors"):
        incoming = router_snapshot.get(key, [])
        if isinstance(incoming, list):
            snapshot.setdefault(key, [])
            for item in incoming:
                if item and item not in snapshot[key]:
                    snapshot[key].append(item)
    if host_table:
        snapshot["available"] = True
        if snapshot.get("source") == "snmp-bridge-fdb":
            snapshot["source"] = "snmp-bridge-fdb+router-webui"
    return snapshot


def _write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")


def _read_snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def collect_topology_snapshot(config: AppConfig, now: datetime) -> dict[str, Any]:
    nodes = _load_topology_nodes(config)
    cache_path = Path(config.topology_cache_json)
    snapshot: dict[str, Any] = {
        "generatedAt": now.isoformat(),
        "enabled": bool(config.topology_enabled),
        "available": False,
        "source": "snmp-bridge-fdb",
        "nodes": [],
        "hostTable": [],
        "errors": [],
        "notes": [],
    }
    if not config.topology_enabled:
        snapshot["notes"].append("Topology discovery disabled.")
        _write_snapshot(cache_path, snapshot)
        return snapshot
    if shutil.which(config.topology_snmpwalk_bin) is None:
        snapshot["errors"].append(f"snmpwalk binary not found: {config.topology_snmpwalk_bin}")
    elif nodes:
        for node in nodes:
            collected_lines: list[str] = []
            node_errors: list[str] = []
            for oid in (
                _DOT1D_BASEPORT_IFINDEX_OID,
                _IF_NAME_OID,
                _IF_DESCR_OID,
                _IF_PHYSADDRESS_OID,
                _DOT1D_TP_FDB_PORT_OID,
                _DOT1Q_TP_FDB_PORT_OID,
            ):
                ok, lines, error = _run_snmpwalk(config, node, oid)
                if lines:
                    collected_lines.extend(lines)
                if not ok and error:
                    node_errors.append(f"{oid}: {error}")
            parsed = _parse_snmpwalk_lines(collected_lines)
            parsed.update(
                {
                    "id": str(node.get("id") or ""),
                    "name": str(node.get("name") or ""),
                    "host": str(node.get("host") or ""),
                    "managementIp": str(node.get("managementIp") or ""),
                    "role": str(node.get("role") or ""),
                    "location": str(node.get("location") or ""),
                    "ok": bool(parsed.get("fdb") or parsed.get("interfaces")),
                    "errors": node_errors,
                }
            )
            snapshot["nodes"].append(parsed)
        _resolve_node_relationships(snapshot)
        snapshot["available"] = any(bool(node.get("ok")) for node in snapshot["nodes"])
        if not snapshot["available"] and not snapshot["errors"]:
            snapshot["notes"].append("No bridge-table data collected from configured nodes.")
    else:
        snapshot["notes"].append("No SNMP topology nodes configured.")
    if config.router_webui_enabled:
        try:
            snapshot = _merge_router_webui_snapshot(snapshot, collect_router_webui_snapshot(config, now.isoformat()))
        except RuntimeError as exc:
            snapshot["errors"].append(str(exc))
    _write_snapshot(cache_path, snapshot)
    return snapshot


def load_topology_snapshot(config: AppConfig, now: datetime, *, allow_refresh: bool = True) -> dict[str, Any]:
    cache_path = Path(config.topology_cache_json)
    snapshot = _read_snapshot(cache_path)
    if not config.topology_enabled:
        if snapshot:
            return snapshot
        return {
            "generatedAt": "",
            "enabled": False,
            "available": False,
            "source": "snmp-bridge-fdb",
            "nodes": [],
            "hostTable": [],
            "errors": [],
            "notes": ["Topology discovery disabled."],
        }
    cached_at_raw = str(snapshot.get("generatedAt") or "")
    cached_at = None
    if cached_at_raw:
        try:
            cached_at = datetime.fromisoformat(cached_at_raw)
        except ValueError:
            cached_at = None
    stale = True
    if cached_at is not None:
        if now.tzinfo is not None and cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=now.tzinfo)
        stale = now - cached_at > timedelta(minutes=max(1, config.topology_refresh_minutes))
    if allow_refresh and (not snapshot or stale):
        return collect_topology_snapshot(config, now)
    return snapshot


def apply_topology_to_inventory(devices: list[dict[str, Any]], topology: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not topology.get("available"):
        return devices, topology
    nodes = topology.get("nodes", [])
    if not isinstance(nodes, list):
        return devices, topology
    device_by_mac = {
        _compact_mac(str(device.get("mac") or "")): device
        for device in devices
        if _compact_mac(str(device.get("mac") or ""))
    }
    node_by_id = {str(node.get("id") or ""): node for node in nodes if isinstance(node, dict)}
    node_by_ip = {str(node.get("managementIp") or ""): node for node in nodes if isinstance(node, dict)}
    host_table = topology.get("hostTable", [])
    if not isinstance(host_table, list):
        host_table = []
    host_by_mac = {
        _compact_mac(str(entry.get("mac") or "")): entry
        for entry in host_table
        if isinstance(entry, dict) and _compact_mac(str(entry.get("mac") or ""))
    }
    host_by_ip = {
        str(entry.get("ip") or ""): entry
        for entry in host_table
        if isinstance(entry, dict) and str(entry.get("ip") or "")
    }
    for device in devices:
        ip = str(device.get("ip") or "")
        mac = _compact_mac(str(device.get("mac") or ""))
        device_is_topology_node = False
        matched_node = node_by_ip.get(ip)
        if matched_node is None and mac:
            for node in nodes:
                interfaces = node.get("interfaces", [])
                if any(_compact_mac(str(interface.get("mac") or "")) == mac for interface in interfaces if isinstance(interface, dict)):
                    matched_node = node
                    break
        if matched_node is not None:
            device_is_topology_node = True
            if str(matched_node.get("location") or "").strip():
                device["location"] = str(matched_node.get("location") or "").strip()
            role = str(matched_node.get("role") or "").strip()
            if role:
                device["role"] = role
            parent_id = str(matched_node.get("parentNodeId") or "")
            parent = node_by_id.get(parent_id)
            if parent is not None:
                device["uplinkIp"] = str(parent.get("managementIp") or "")
                device["uplinkName"] = str(parent.get("name") or "")
                device["uplinkRole"] = str(parent.get("role") or "")
        if device_is_topology_node:
            continue
        if not mac:
            continue
        candidates: list[dict[str, Any]] = []
        for node in nodes:
            fdb_entries = node.get("fdb", [])
            if any(_compact_mac(str(entry.get("mac") or "")) == mac for entry in fdb_entries if isinstance(entry, dict)):
                candidates.append(node)
        if not candidates:
            continue
        chosen = sorted(candidates, key=_node_rank, reverse=True)[0]
        if str(chosen.get("location") or "").strip():
            device["location"] = str(chosen.get("location") or "").strip()
        device["uplinkIp"] = str(chosen.get("managementIp") or "")
        device["uplinkName"] = str(chosen.get("name") or "")
        device["uplinkRole"] = str(chosen.get("role") or "")
        if str(chosen.get("role") or "").strip() in {"extender", "access_point", "mesh", "switch", "bridge"}:
            device["placementReason"] = f"Learned from {chosen.get('name') or chosen.get('managementIp')}"
        continue
        
    for device in devices:
        if str(device.get("uplinkIp") or "").strip():
            continue
        ip = str(device.get("ip") or "")
        mac = _compact_mac(str(device.get("mac") or ""))
        matched_host = host_by_mac.get(mac) or host_by_ip.get(ip)
        if matched_host is None:
            continue
        device["uplinkIp"] = str(matched_host.get("sourceManagementIp") or "")
        device["uplinkName"] = str(matched_host.get("sourceNodeName") or "")
        device["uplinkRole"] = str(matched_host.get("sourceNodeRole") or "")
        device["placementReason"] = "Seen in router host table"
    for node in nodes:
        node["attachedDevices"] = []
    for device in devices:
        parent_ip = str(device.get("uplinkIp") or "")
        if not parent_ip:
            continue
        node = node_by_ip.get(parent_ip)
        if node is None:
            continue
        node.setdefault("attachedDevices", []).append(
            {
                "id": str(device.get("id") or ""),
                "name": str(device.get("name") or device.get("hostname") or device.get("ip") or "Unknown device"),
                "ip": str(device.get("ip") or ""),
                "category": str(device.get("category") or "unknown"),
                "categoryLabel": str(device.get("categoryLabel") or "Unknown"),
            }
        )
    for node in nodes:
        node["attachedDeviceCount"] = len(node.get("attachedDevices", []))
    return devices, topology
