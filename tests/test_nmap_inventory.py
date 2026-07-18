from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from pi_probe_discord.nmap_inventory import export_nmap_inventory_json, remove_nmap_override, upsert_nmap_override
from tests.test_dashboard import make_config


class NmapInventoryTests(unittest.TestCase):
    def test_export_nmap_inventory_json_identifies_bambu_by_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV --script ssl-cert 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.77" addrtype="ipv4"/>
    <hostnames><hostname name="printer"/></hostnames>
    <os><osmatch name="Linux 5.x" accuracy="98"/></os>
    <ports>
      <port protocol="tcp" portid="990">
        <state state="open"/>
        <service name="ssl/ftp" product="vsftpd" version="3.0.5" tunnel="ssl"/>
        <script id="ssl-cert" output="Subject: commonName=22E8BJ5C1401474 Issuer: organizationName=BBL Technologies Co. Ltd commonName=BBL Device CA X509v3 extensions: Printer"/>
      </port>
      <port protocol="tcp" portid="3000"><state state="open"/><service name="tcpwrapped"/></port>
      <port protocol="tcp" portid="6000"><state state="open"/><service name="tcpwrapped"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            device = payload["devices"][0]
            self.assertEqual(device["name"], "Bambu Lab 3D Printer")
            self.assertEqual(device["category"], "printer")
            self.assertEqual(device["categoryLabel"], "3D Printer")
            self.assertEqual(device["manufacturer"], "Bambu Lab")
            self.assertEqual(device["deviceType"], "3d_printer")
            self.assertEqual(device["identificationConfidence"], "confirmed")
            self.assertEqual(device["deviceId"], "22E8BJ5C1401474")
            self.assertTrue(any("bbl technologies co. ltd" in reason.lower() for reason in device["identificationReasons"]))

    def test_export_nmap_inventory_json_marks_probable_bambu_without_cert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.88" addrtype="ipv4"/>
    <hostnames><hostname name="mystery-device"/></hostnames>
    <os><osmatch name="Embedded Linux" accuracy="95"/></os>
    <ports>
      <port protocol="tcp" portid="990"><state state="open"/><service name="ssl/ftp" product="vsftpd" version="3.0.5" tunnel="ssl"/></port>
      <port protocol="tcp" portid="3000"><state state="open"/><service name="tcpwrapped"/></port>
      <port protocol="tcp" portid="6000"><state state="open"/><service name="tcpwrapped"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            device = payload["devices"][0]
            self.assertEqual(device["name"], "Possible Bambu Lab 3D Printer")
            self.assertEqual(device["identificationConfidence"], "probable")

    def test_export_nmap_inventory_json_does_not_false_positive_on_port_3000(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
    <hostnames><hostname name="grafana"/></hostnames>
    <ports>
      <port protocol="tcp" portid="3000"><state state="open"/><service name="http" product="Grafana"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            device = payload["devices"][0]
            self.assertNotEqual(device["category"], "printer")
            self.assertNotIn("Bambu", device["name"])

    def test_export_nmap_inventory_json_parses_hosts_and_categories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TP-Link"/>
    <hostnames><hostname name="archer-router"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.120" addrtype="ipv4"/>
    <hostnames><hostname name="living-room-tv"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8009"><state state="open"/><service name="googlecast"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["network"], "192.168.1.0/24")
            self.assertEqual(payload["deviceCount"], 2)
            categories = {item["ip"]: item["category"] for item in payload["devices"]}
            self.assertEqual(categories["192.168.1.1"], "infrastructure")
            self.assertEqual(categories["192.168.1.120"], "media")

    def test_export_nmap_inventory_json_emits_change_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            xml_path = Path(config.nmap_inventory_xml)
            xml_path.write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            events_payload = json.loads(Path(config.nmap_events_json).read_text(encoding="utf-8"))
            self.assertEqual(events_payload["events"][0]["event_type"], "new_host")

            xml_path.write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 21, 0, 0))
            self.assertTrue(ok)
            events_payload = json.loads(Path(config.nmap_events_json).read_text(encoding="utf-8"))
            event_types = [event["event_type"] for event in events_payload["events"]]
            self.assertIn("port_opened", event_types)

    def test_export_nmap_inventory_json_applies_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_overrides_json).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -F 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.107" addrtype="ipv4"/>
    <address addr="44:42:01:86:4B:39" addrtype="mac" vendor="Amazon Technologies"/>
    <hostnames><hostname name="echo-box"/></hostnames>
    <ports>
      <port protocol="tcp" portid="5000"><state state="open"/><service name="upnp"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            Path(config.nmap_overrides_json).write_text(
                json.dumps(
                    {
                        "devices": [
                            {
                                "mac": "44:42:01:86:4B:39",
                                "name": "Kitchen Echo",
                                "category": "media",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["devices"][0]["name"], "Kitchen Echo")
            self.assertEqual(payload["devices"][0]["category"], "media")
            self.assertEqual(payload["devices"][0]["categoryLabel"], "Media")

    def test_export_nmap_inventory_json_override_wins_over_bambu_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_overrides_json).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV --script ssl-cert 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.77" addrtype="ipv4"/>
    <hostnames><hostname name="printer"/></hostnames>
    <ports>
      <port protocol="tcp" portid="990">
        <state state="open"/>
        <service name="ssl/ftp" product="vsftpd" version="3.0.5" tunnel="ssl"/>
        <script id="ssl-cert" output="Issuer: organizationName=BBL Technologies Co. Ltd Subject: commonName=22E8BJ5C1401474 Printer"/>
      </port>
      <port protocol="tcp" portid="3000"><state state="open"/><service name="tcpwrapped"/></port>
      <port protocol="tcp" portid="6000"><state state="open"/><service name="tcpwrapped"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            Path(config.nmap_overrides_json).write_text(
                json.dumps({"devices": [{"ip": "192.168.1.77", "name": "Workshop Printer", "category": "servers"}]}),
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            device = payload["devices"][0]
            self.assertEqual(device["name"], "Workshop Printer")
            self.assertEqual(device["category"], "servers")

    def test_export_nmap_inventory_json_merges_multi_interface_device_by_device_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV --script ssl-cert 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.77" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="990"><state state="open"/><service name="ssl/ftp" product="vsftpd" version="3.0.5" tunnel="ssl"/><script id="ssl-cert" output="Issuer: organizationName=BBL Technologies Co. Ltd Subject: commonName=22E8BJ5C1401474 Printer"/></port>
      <port protocol="tcp" portid="3000"><state state="open"/><service name="tcpwrapped"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.78" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="990"><state state="open"/><service name="ssl/ftp" product="vsftpd" version="3.0.5" tunnel="ssl"/><script id="ssl-cert" output="Issuer: organizationName=BBL Technologies Co. Ltd Subject: commonName=22E8BJ5C1401474 Printer"/></port>
      <port protocol="tcp" portid="6000"><state state="open"/><service name="tcpwrapped"/></port>
    </ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["rawDeviceCount"], 2)
            self.assertEqual(payload["deviceCount"], 1)
            self.assertEqual(sorted(payload["devices"][0]["ips"]), ["192.168.1.77", "192.168.1.78"])

    def test_export_nmap_inventory_json_keeps_similar_devices_separate_without_reliable_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_xml).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_xml).write_text(
                """<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.0/24">
  <host>
    <status state="up"/>
    <address addr="192.168.1.51" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.52" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
  </host>
</nmaprun>
""",
                encoding="utf-8",
            )
            ok, _ = export_nmap_inventory_json(config, datetime(2026, 6, 8, 20, 0, 0))
            self.assertTrue(ok)
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["deviceCount"], 2)

    def test_old_inventory_json_without_identification_fields_is_still_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.nmap_inventory_json).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_json).write_text(
                json.dumps(
                    {
                        "scannedAt": "2026-06-06T10:15:00",
                        "devices": [
                            {
                                "id": "192.168.1.1",
                                "name": "Router",
                                "hostname": "router",
                                "ip": "192.168.1.1",
                                "mac": "",
                                "vendor": "TP-Link",
                                "status": "up",
                                "category": "infrastructure",
                                "categoryLabel": "Infrastructure",
                                "accent": "cyan",
                                "ports": [],
                                "openPorts": [],
                                "services": [],
                                "portCount": 0,
                                "lastSeen": "2026-06-06T10:15:00",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            payload = json.loads(Path(config.nmap_inventory_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["devices"][0]["name"], "Router")

    def test_override_upsert_and_remove(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            message = upsert_nmap_override(
                config,
                ip="192.168.1.51",
                name="Pi Probe",
                category="servers",
            )
            self.assertIn("Saved Nmap override", message)
            payload = json.loads(Path(config.nmap_overrides_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["devices"][0]["ip"], "192.168.1.51")
            self.assertEqual(payload["devices"][0]["name"], "Pi Probe")
            self.assertEqual(payload["devices"][0]["category"], "servers")

            message = remove_nmap_override(config, ip="192.168.1.51")
            self.assertIn("Removed Nmap override", message)
            payload = json.loads(Path(config.nmap_overrides_json).read_text(encoding="utf-8"))
            self.assertEqual(payload["devices"], [])


if __name__ == "__main__":
    unittest.main()
