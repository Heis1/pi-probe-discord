from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from pi_probe_discord.topology import apply_topology_to_inventory, collect_topology_snapshot
from tests.test_dashboard import make_config


class TopologyTests(unittest.TestCase):
    def test_collect_topology_snapshot_parses_bridge_tables_and_links_extender_to_router(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.topology_enabled = True
            config.topology_nodes_json = """
[
  {"id":"router","name":"Main Router","host":"192.168.1.1","management_ip":"192.168.1.1","community":"public","role":"router","location":"Main Network"},
  {"id":"extender","name":"Downstairs Extender","host":"192.168.1.115","management_ip":"192.168.1.115","community":"public","role":"extender","location":"Downstairs"}
]
""".strip()
            outputs = {
                ("192.168.1.1", ".1.3.6.1.2.1.17.1.4.1.2"): ".1.3.6.1.2.1.17.1.4.1.2.1 = INTEGER: 1\n.1.3.6.1.2.1.17.1.4.1.2.2 = INTEGER: 2\n",
                ("192.168.1.1", ".1.3.6.1.2.1.31.1.1.1.1"): ".1.3.6.1.2.1.31.1.1.1.1.1 = STRING: br0\n.1.3.6.1.2.1.31.1.1.1.1.2 = STRING: lan1\n",
                ("192.168.1.1", ".1.3.6.1.2.1.2.2.1.2"): ".1.3.6.1.2.1.2.2.1.2.1 = STRING: br0\n.1.3.6.1.2.1.2.2.1.2.2 = STRING: lan1\n",
                ("192.168.1.1", ".1.3.6.1.2.1.2.2.1.6"): ".1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: AA BB CC DD EE 01\n.1.3.6.1.2.1.2.2.1.6.2 = Hex-STRING: AA BB CC DD EE 02\n",
                ("192.168.1.1", ".1.3.6.1.2.1.17.4.3.1.2"): ".1.3.6.1.2.1.17.4.3.1.2.120.50.27.189.65.8 = INTEGER: 2\n",
                ("192.168.1.1", ".1.3.6.1.2.1.17.7.1.2.2.1.2"): "",
                ("192.168.1.115", ".1.3.6.1.2.1.17.1.4.1.2"): ".1.3.6.1.2.1.17.1.4.1.2.1 = INTEGER: 1\n",
                ("192.168.1.115", ".1.3.6.1.2.1.31.1.1.1.1"): ".1.3.6.1.2.1.31.1.1.1.1.1 = STRING: wlan0\n",
                ("192.168.1.115", ".1.3.6.1.2.1.2.2.1.2"): ".1.3.6.1.2.1.2.2.1.2.1 = STRING: wlan0\n",
                ("192.168.1.115", ".1.3.6.1.2.1.2.2.1.6"): ".1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 78 32 1B BD 41 08\n",
                ("192.168.1.115", ".1.3.6.1.2.1.17.4.3.1.2"): ".1.3.6.1.2.1.17.4.3.1.2.238.25.135.150.158.124 = INTEGER: 1\n",
                ("192.168.1.115", ".1.3.6.1.2.1.17.7.1.2.2.1.2"): "",
            }

            def fake_run(command, capture_output=None, text=None, timeout=None, check=None):
                host = command[-2]
                oid = command[-1]
                class Result:
                    returncode = 0
                    stdout = outputs.get((host, oid), "")
                    stderr = ""
                return Result()

            with patch("pi_probe_discord.topology.shutil.which", return_value="/usr/bin/snmpwalk"), \
                 patch("pi_probe_discord.topology.subprocess.run", side_effect=fake_run):
                snapshot = collect_topology_snapshot(config, datetime(2026, 7, 18, 15, 0, 0))

            self.assertTrue(snapshot["available"])
            nodes = {item["id"]: item for item in snapshot["nodes"]}
            self.assertEqual(nodes["extender"]["parentNodeId"], "router")
            self.assertEqual(nodes["extender"]["parentManagementIp"], "192.168.1.1")

    def test_apply_topology_to_inventory_assigns_extender_location_automatically(self) -> None:
        devices = [
            {"id": "192.168.1.115", "ip": "192.168.1.115", "mac": "78:32:1B:BD:41:08", "name": "D-Link", "category": "infrastructure", "categoryLabel": "Infrastructure"},
            {"id": "192.168.1.102", "ip": "192.168.1.102", "mac": "EE:19:87:96:9E:7C", "name": "Samsung Galaxy Phone", "category": "mobile", "categoryLabel": "Mobile"},
        ]
        topology = {
            "available": True,
            "nodes": [
                {
                    "id": "router",
                    "name": "Main Router",
                    "managementIp": "192.168.1.1",
                    "role": "router",
                    "location": "Main Network",
                    "parentNodeId": "",
                    "interfaces": [{"mac": "AA:BB:CC:DD:EE:01"}],
                    "fdb": [{"mac": "78:32:1b:bd:41:08"}],
                    "depth": 0,
                },
                {
                    "id": "extender",
                    "name": "Downstairs Extender",
                    "managementIp": "192.168.1.115",
                    "role": "extender",
                    "location": "Downstairs",
                    "parentNodeId": "router",
                    "interfaces": [{"mac": "78:32:1b:bd:41:08"}],
                    "fdb": [{"mac": "ee:19:87:96:9e:7c"}],
                    "depth": 1,
                },
            ],
        }

        updated_devices, updated_topology = apply_topology_to_inventory(devices, topology)
        by_ip = {item["ip"]: item for item in updated_devices}
        self.assertEqual(by_ip["192.168.1.115"]["location"], "Downstairs")
        self.assertEqual(by_ip["192.168.1.115"]["role"], "extender")
        self.assertEqual(by_ip["192.168.1.102"]["location"], "Downstairs")
        self.assertEqual(by_ip["192.168.1.102"]["uplinkIp"], "192.168.1.115")
        nodes = {item["id"]: item for item in updated_topology["nodes"]}
        self.assertEqual(nodes["extender"]["attachedDeviceCount"], 1)


if __name__ == "__main__":
    unittest.main()
