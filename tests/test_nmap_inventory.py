from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from pi_probe_discord.nmap_inventory import export_nmap_inventory_json, remove_nmap_override, upsert_nmap_override
from tests.test_dashboard import make_config


class NmapInventoryTests(unittest.TestCase):
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
