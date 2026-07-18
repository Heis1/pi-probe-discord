from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
import json
from multiprocessing import Process
from pathlib import Path
import sqlite3
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from pi_probe_discord.dashboard import (
    NmapDeviceRow,
    RouterEvent,
    _version_string,
    apply_dashboard_nmap_override,
    build_network_diagnosis,
    build_dashboard_summary,
    generate_interactive_dashboard,
    generate_premium_dashboard,
    ping_dashboard_device,
    run_dashboard_nmap_scan,
    serve_interactive_dashboard,
)
from pi_probe_discord.models import AppConfig, RouterSnapshot, SpeedResult


def make_config(base_dir: Path) -> AppConfig:
    return AppConfig(
        webhook_url="https://discord.invalid/webhook",
        config_file=str(base_dir / "env"),
        log_file=str(base_dir / "probe.log"),
        chart_file=str(base_dir / "speed_chart.png"),
        firewall_chart_file=str(base_dir / "firewall.png"),
        dashboard_style="premium",
        interactive_dashboard_enabled=True,
        interactive_dashboard_file=str(base_dir / "dashboard" / "index.html"),
        interactive_dashboard_host="127.0.0.1",
        interactive_dashboard_port=8088,
        interactive_dashboard_tls_enabled=False,
        interactive_dashboard_tls_cert_file=str(base_dir / "dashboard-cert.pem"),
        interactive_dashboard_tls_key_file=str(base_dir / "dashboard-key.pem"),
        interactive_dashboard_api_token="",
        dashboard_refresh_seconds=60,
        public_dashboard_url="https://example.com/dashboard",
        dashboard_link_label="Open Interactive Dashboard",
        outage_download_mbps=50.0,
        degraded_download_mbps=250.0,
        high_ping_ms=20.0,
        failed_test_is_outage=True,
        heatmap_good_mbps=320.0,
        heatmap_warn_mbps=250.0,
        router_events_csv=str(base_dir / "events" / "router_events.csv"),
        router_events_json=str(base_dir / "events" / "router_events.json"),
        pihole_hourly_csv=str(base_dir / "pihole" / "pihole_hourly.csv"),
        pihole_ftl_db_path=str(base_dir / "pihole-FTL.db"),
        nmap_inventory_xml=str(base_dir / "nmap" / "latest.xml"),
        nmap_inventory_json=str(base_dir / "nmap" / "latest.json"),
        nmap_events_json=str(base_dir / "nmap" / "events.json"),
        nmap_overrides_json=str(base_dir / "nmap" / "overrides.json"),
        nmap_state_json=str(base_dir / "nmap" / "state.json"),
        nmap_targets="192.168.1.0/24",
        nmap_arguments="-F --min-rate 2000 --host-timeout 30s",
        nmap_scan_minutes=360,
        db_path=str(base_dir / "probe.db"),
        history_retention_days=365,
        request_timeout=30,
        max_text_field_length=1200,
        speedtest_schedule_minutes=60,
        full_report_schedule="03:30",
        firewall_enabled=True,
        firewall_window_hours=24,
        firewall_top_n=5,
        firewall_noisy_source_threshold=10,
        firewall_include_allow=False,
        firewall_log_paths=[],
        firewall_alert_enabled=False,
        firewall_alert_min_blocks=80,
        firewall_alert_min_ssh_attempts=20,
        firewall_alert_min_noisy_sources=2,
        firewall_alert_cooldown_minutes=60,
        firewall_alert_state_file=str(base_dir / "firewall_state.json"),
        router_snmp_enabled=False,
        router_snmp_log_path=str(base_dir / "snmp.log"),
        router_snmp_state_file=str(base_dir / "snmp_state.json"),
        router_snmp_window_hours=24,
        router_snmp_top_n=5,
        router_snmp_listener_enabled=False,
        router_snmp_bind_host="127.0.0.1",
        router_snmp_bind_port=9162,
        router_snmp_max_events_per_minute=120,
        router_snmp_max_packet_bytes=4096,
        router_snmp_oid_severity_map={},
        topology_enabled=False,
        topology_nodes_json="",
        topology_cache_json=str(base_dir / "topology" / "latest.json"),
        topology_refresh_minutes=30,
        topology_snmpwalk_bin="snmpwalk",
        topology_snmp_timeout_seconds=6,
        router_webui_enabled=False,
        router_webui_url="http://192.168.1.1",
        router_webui_secret_file=str(base_dir / "router-webui.env"),
    )


class DashboardTests(unittest.TestCase):
    def test_network_diagnosis_marks_recently_recovered_when_suspect_is_back(self) -> None:
        now = datetime(2026, 7, 3, 15, 0, 0)
        config = make_config(Path(tempfile.mkdtemp()))
        diagnosis = build_network_diagnosis(
            events=[
                RouterEvent(
                    timestamp=now - timedelta(hours=2),
                    event_type="host_missing",
                    message="Host missing from latest scan: D-Link International",
                    severity="warning",
                    source="192.168.1.101",
                )
            ],
            nmap_rows=[
                NmapDeviceRow(
                    device_id="192.168.1.101",
                    name="D-Link International",
                    hostname="dlink-extender",
                    ip="192.168.1.101",
                    mac="AA:BB:CC:DD:EE:10",
                    vendor="D-Link International",
                    status="up",
                    category="infrastructure",
                    category_label="Infrastructure",
                    accent="cyan",
                    ports=[],
                    open_ports=[],
                    services=[],
                    port_count=0,
                    last_seen=now.isoformat(),
                )
            ],
            nmap_meta={"scannedAt": (now - timedelta(minutes=10)).isoformat()},
            now=now,
            config=config,
        )
        self.assertEqual(diagnosis["status"], "resolved")
        self.assertEqual(diagnosis["statusLabel"], "Recently Recovered")
        self.assertTrue(diagnosis["inventoryFresh"])
        self.assertEqual(diagnosis["eventWindowHours"], 24)

    def test_network_diagnosis_marks_stale_when_inventory_is_old(self) -> None:
        now = datetime(2026, 7, 3, 15, 0, 0)
        config = make_config(Path(tempfile.mkdtemp()))
        diagnosis = build_network_diagnosis(
            events=[
                RouterEvent(
                    timestamp=now - timedelta(hours=3),
                    event_type="host_missing",
                    message="Host missing from latest scan: D-Link International",
                    severity="warning",
                    source="192.168.1.101",
                )
            ],
            nmap_rows=[],
            nmap_meta={"scannedAt": (now - timedelta(hours=13)).isoformat()},
            now=now,
            config=config,
        )
        self.assertEqual(diagnosis["status"], "stale")
        self.assertEqual(diagnosis["statusLabel"], "Stale Incident")
        self.assertFalse(diagnosis["inventoryFresh"])

    def test_build_dashboard_summary_classifies_rows(self) -> None:
        now = datetime(2026, 6, 6, 12, 0, 0)
        config = make_config(Path(tempfile.mkdtemp()))
        run_rows = [
            {"recorded_at": (now - timedelta(hours=3)).isoformat(), "speed_ok": True, "download_mbps": 330.0, "upload_mbps": 45.0, "ping_ms": 4.0},
            {"recorded_at": (now - timedelta(hours=2)).isoformat(), "speed_ok": True, "download_mbps": 180.0, "upload_mbps": 43.0, "ping_ms": 5.0},
            {"recorded_at": (now - timedelta(hours=1)).isoformat(), "speed_ok": True, "download_mbps": 40.0, "upload_mbps": 41.0, "ping_ms": 8.0},
            {"recorded_at": now.isoformat(), "speed_ok": False, "download_mbps": None, "upload_mbps": None, "ping_ms": None},
        ]
        summary = build_dashboard_summary({"download": [], "upload": [], "ping": []}, now, config=config, run_rows=run_rows)
        stats = summary["stats"]
        self.assertEqual(stats["failedCount"], 1)
        self.assertEqual(stats["degradedCount"], 1)
        self.assertEqual(stats["outageCount"], 2)
        self.assertEqual(stats["longestOutageStreak"], 2)
        self.assertGreater(summary["score"]["total"], 0)

    def test_build_dashboard_summary_ignores_impossible_ping_outlier(self) -> None:
        now = datetime(2026, 6, 6, 12, 0, 0)
        config = make_config(Path(tempfile.mkdtemp()))
        run_rows = [
            {"recorded_at": (now - timedelta(hours=2)).isoformat(), "speed_ok": True, "download_mbps": 320.0, "upload_mbps": 44.0, "ping_ms": 4.0},
            {"recorded_at": (now - timedelta(hours=1)).isoformat(), "speed_ok": True, "download_mbps": 318.0, "upload_mbps": 43.0, "ping_ms": 8250.06},
        ]
        summary = build_dashboard_summary({"download": [], "upload": [], "ping": []}, now, config=config, run_rows=run_rows)
        stats = summary["stats"]
        self.assertEqual(stats["avgPing"], 4.0)
        self.assertEqual(stats["failedCount"], 1)
        self.assertEqual(stats["outageCount"], 1)

    def test_generate_premium_dashboard_handles_sparse_heatmap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            now = datetime(2026, 6, 6, 12, 0, 0)
            history = {
                "download": [
                    {"x": (now - timedelta(hours=2)).isoformat(), "y": 320.0},
                    {"x": (now - timedelta(hours=1)).isoformat(), "y": 240.0},
                ],
                "upload": [
                    {"x": (now - timedelta(hours=2)).isoformat(), "y": 44.0},
                    {"x": (now - timedelta(hours=1)).isoformat(), "y": 42.0},
                ],
                "ping": [
                    {"x": (now - timedelta(hours=2)).isoformat(), "y": 4.0},
                    {"x": (now - timedelta(hours=1)).isoformat(), "y": 5.0},
                ],
            }

            ok, message = generate_premium_dashboard(
                history,
                now,
                str(base / "speed_chart.png"),
                SpeedResult(ok=True, summary="Download 240 Mbps | Upload 42 Mbps | Ping 5 ms", download_mbps=240.0, upload_mbps=42.0, ping_ms=5.0),
            )

            if message == "matplotlib not installed":
                self.skipTest("matplotlib not installed")
            self.assertTrue(ok, message)
            self.assertTrue((base / "speed_chart.png").exists())

    def test_version_string_falls_back_to_dpkg_version(self) -> None:
        with patch("pi_probe_discord.version_check.current_version", return_value="1.1.7-1"):
            self.assertEqual(_version_string(), "1.1.7-1")

    def test_generate_dashboard_writes_status_and_optional_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            Path(config.router_events_csv).parent.mkdir(parents=True, exist_ok=True)
            Path(config.pihole_hourly_csv).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_json).parent.mkdir(parents=True, exist_ok=True)
            Path(config.router_events_csv).write_text(
                "timestamp,event_type,message,severity,source\n2026-06-06T10:00:00,wan_disconnect,Carrier lost,critical,router\n",
                encoding="utf-8",
            )
            Path(config.pihole_hourly_csv).write_text(
                "datetime,dns_queries,blocked_queries,blocked_percent\n2026-06-06T10:00:00,1200,210,17.5\n",
                encoding="utf-8",
            )
            Path(config.nmap_inventory_json).write_text(
                json.dumps(
                    {
                        "scannedAt": "2026-06-06T10:15:00",
                        "network": "192.168.1.0/24",
                        "deviceCount": 2,
                        "devices": [
                            {
                                "id": "192.168.1.1",
                                "name": "TP-Link Router",
                                "hostname": "archer",
                                "ip": "192.168.1.1",
                                "mac": "AA:BB:CC:DD:EE:01",
                                "vendor": "TP-Link",
                                "status": "up",
                                "category": "infrastructure",
                                "categoryLabel": "Infrastructure",
                                "accent": "cyan",
                                "ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
                                "openPorts": [443],
                                "services": ["https"],
                                "portCount": 1,
                                "lastSeen": "2026-06-06T10:15:00",
                            },
                            {
                                "id": "192.168.1.51",
                                "name": "Pi-hole",
                                "hostname": "pi.hole",
                                "ip": "192.168.1.51",
                                "mac": "AA:BB:CC:DD:EE:FF",
                                "vendor": "Raspberry Pi",
                                "status": "up",
                                "category": "servers",
                                "categoryLabel": "Servers",
                                "accent": "green",
                                "ports": [{"port": 53, "protocol": "tcp", "service": "domain"}],
                                "openPorts": [53],
                                "services": ["domain"],
                                "portCount": 1,
                                "lastSeen": "2026-06-06T10:15:00",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            now = datetime(2026, 6, 6, 12, 0, 0)
            run_rows = [
                {"recorded_at": (now - timedelta(hours=2)).isoformat(), "speed_ok": True, "download_mbps": 320.0, "upload_mbps": 44.0, "ping_ms": 4.0},
                {"recorded_at": (now - timedelta(hours=1)).isoformat(), "speed_ok": True, "download_mbps": 240.0, "upload_mbps": 42.0, "ping_ms": 5.0},
            ]
            ok, _ = generate_interactive_dashboard(
                {"download": [], "upload": [], "ping": []},
                now,
                config.interactive_dashboard_file,
                config=config,
                run_rows=run_rows,
            )
            self.assertTrue(ok)
            html = Path(config.interactive_dashboard_file).read_text(encoding="utf-8")
            status = json.loads((Path(config.interactive_dashboard_file).parent / "status.json").read_text(encoding="utf-8"))
            self.assertIn("wan_disconnect", html)
            self.assertIn("https://example.com/dashboard", html)
            self.assertIn("blockedQueries", html)
            self.assertIn("Network Devices", html)
            self.assertIn("TP-Link Router", html)
            self.assertIn("Run Nmap Scan", html)
            self.assertIn("scanTargets", html)
            self.assertIn('"mac": "AA:BB:CC:DD:EE:FF"', html)
            self.assertIn("Clear override", html)
            self.assertEqual(status["service"], "pi-probe-discord-dashboard")
            self.assertEqual(status["test_count"], 2)

    def test_run_dashboard_nmap_scan_refreshes_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            with patch("pi_probe_discord.config.load_config", return_value=config), \
                 patch("pi_probe_discord.nmap_inventory.run_nmap_inventory_scan", return_value=(True, "scan ok")), \
                 patch("pi_probe_discord.storage.load_history_from_db", return_value={"download": [], "upload": [], "ping": []}), \
                 patch("pi_probe_discord.storage.load_probe_runs_from_db", return_value=[]), \
                 patch("pi_probe_discord.pihole_hourly.export_pihole_hourly_csv", return_value=(True, "exported")), \
                 patch("pi_probe_discord.dashboard.generate_interactive_dashboard", return_value=(True, "dashboard refreshed")) as refresh_mock:
                result = run_dashboard_nmap_scan(config.interactive_dashboard_file)

            self.assertTrue(result["ok"])
            self.assertTrue(result["scanOk"])
            self.assertTrue(result["refreshOk"])
            self.assertEqual(result["message"], "dashboard refreshed")
            refresh_mock.assert_called_once()

    def test_apply_dashboard_nmap_override_refreshes_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            with patch("pi_probe_discord.config.load_config", return_value=config), \
                 patch("pi_probe_discord.nmap_inventory.upsert_nmap_override", return_value="override saved") as upsert_mock, \
                 patch("pi_probe_discord.nmap_inventory.export_nmap_inventory_json", return_value=(True, "inventory refreshed")), \
                 patch("pi_probe_discord.storage.load_history_from_db", return_value={"download": [], "upload": [], "ping": []}), \
                 patch("pi_probe_discord.storage.load_probe_runs_from_db", return_value=[]), \
                 patch("pi_probe_discord.pihole_hourly.export_pihole_hourly_csv", return_value=(True, "exported")), \
                 patch("pi_probe_discord.dashboard.generate_interactive_dashboard", return_value=(True, "dashboard refreshed")) as refresh_mock:
                result = apply_dashboard_nmap_override(
                    config.interactive_dashboard_file,
                    {
                        "action": "set",
                        "selector": {"ip": "192.168.1.51", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "pi.hole"},
                        "name": "Office Pi-hole",
                        "category": "servers",
                    },
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["message"], "override saved")
            upsert_mock.assert_called_once()
            refresh_mock.assert_called_once()

    def test_apply_dashboard_nmap_override_prefers_single_mac_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            with patch("pi_probe_discord.config.load_config", return_value=config), \
                 patch("pi_probe_discord.nmap_inventory.upsert_nmap_override", return_value="override saved") as upsert_mock, \
                 patch("pi_probe_discord.nmap_inventory.export_nmap_inventory_json", return_value=(True, "inventory refreshed")), \
                 patch("pi_probe_discord.storage.load_history_from_db", return_value={"download": [], "upload": [], "ping": []}), \
                 patch("pi_probe_discord.storage.load_probe_runs_from_db", return_value=[]), \
                 patch("pi_probe_discord.pihole_hourly.export_pihole_hourly_csv", return_value=(True, "exported")), \
                 patch("pi_probe_discord.dashboard.generate_interactive_dashboard", return_value=(True, "dashboard refreshed")):
                result = apply_dashboard_nmap_override(
                    config.interactive_dashboard_file,
                    {
                        "action": "set",
                        "selector": {"ip": "192.168.1.101", "mac": "78:32:1B:BD:41:08", "hostname": "dlink"},
                        "name": "D-Link International",
                        "category": "servers",
                    },
                )

            self.assertTrue(result["ok"])
            upsert_mock.assert_called_once_with(
                config,
                ip="192.168.1.101",
                mac="78:32:1B:BD:41:08",
                hostname="dlink",
                name="D-Link International",
                category="servers",
                role="",
                location="",
                uplink_ip="",
            )

    def test_generate_dashboard_includes_router_snmp_db_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            with sqlite3.connect(config.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE router_snmp_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        recorded_at TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        trap_oid TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        raw_line TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO router_snmp_events (recorded_at, source_ip, trap_oid, summary, raw_line)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-06-06T10:00:00",
                        "192.168.1.1",
                        "SNMPv2-MIB::warmStart",
                        "Router warm start detected",
                        "raw trap line",
                    ),
                )
            now = datetime(2026, 6, 6, 12, 0, 0)
            run_rows = [
                {"recorded_at": (now - timedelta(hours=2)).isoformat(), "speed_ok": True, "download_mbps": 320.0, "upload_mbps": 44.0, "ping_ms": 4.0},
                {"recorded_at": (now - timedelta(hours=1)).isoformat(), "speed_ok": True, "download_mbps": 240.0, "upload_mbps": 42.0, "ping_ms": 5.0},
            ]
            ok, _ = generate_interactive_dashboard(
                {"download": [], "upload": [], "ping": []},
                now,
                config.interactive_dashboard_file,
                config=config,
                run_rows=run_rows,
            )
            self.assertTrue(ok)
            html = Path(config.interactive_dashboard_file).read_text(encoding="utf-8")
            self.assertIn("SNMPv2-MIB::warmStart", html)
            self.assertIn("192.168.1.1", html)

    def test_build_network_diagnosis_flags_extender_disappearance(self) -> None:
        now = datetime(2026, 7, 2, 17, 0, 0)
        diagnosis = build_network_diagnosis(
            [
                RouterEvent(
                    timestamp=now - timedelta(minutes=30),
                    event_type="host_missing",
                    message="Host missing from latest scan: D-Link Range Extender",
                    severity="warning",
                    source="192.168.1.55",
                ),
                RouterEvent(
                    timestamp=now - timedelta(minutes=25),
                    event_type="port_closed",
                    message="Closed port(s): 80 on D-Link Range Extender",
                    severity="info",
                    source="192.168.1.55",
                ),
            ],
            [
                NmapDeviceRow(
                    device_id="192.168.1.1",
                    name="Archer Router",
                    hostname="archer-router",
                    ip="192.168.1.1",
                    mac="AA:BB:CC:DD:EE:FF",
                    vendor="TP-Link",
                    status="up",
                    category="infrastructure",
                    category_label="Infrastructure",
                    accent="cyan",
                    ports=[],
                    open_ports=[],
                    services=[],
                    port_count=0,
                    last_seen=(now - timedelta(hours=1)).isoformat(),
                ),
            ],
            {"scannedAt": (now - timedelta(minutes=20)).isoformat(), "deviceCount": 1, "network": "192.168.1.0/24"},
            now=now,
            router_snapshot=RouterSnapshot(
                enabled=True,
                ingest_source="udp://0.0.0.0:162",
                ingested_events=0,
                window_hours=24,
                recent_events=2,
                link_down_events=1,
                auth_fail_events=0,
            ),
        )
        self.assertEqual(diagnosis["status"], "critical")
        self.assertEqual(diagnosis["hostMissingCount"], 1)
        self.assertIn("extender", diagnosis["headline"].lower())

    def test_ping_dashboard_device_reports_latency(self) -> None:
        with patch("pi_probe_discord.dashboard._run_optional_command", return_value=(True, "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.31 ms")):
            result = ping_dashboard_device({"ip": "192.168.1.1", "name": "Router"})
        self.assertTrue(result["ok"])
        self.assertIn("2.31 ms", result["message"])

    def test_dashboard_server_health_and_status_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dashboard_dir = base / "dashboard"
            dashboard_dir.mkdir(parents=True, exist_ok=True)
            dashboard_file = dashboard_dir / "index.html"
            status_file = dashboard_dir / "status.json"
            dashboard_file.write_text("<html><body>dashboard</body></html>", encoding="utf-8")
            status_file.write_text(json.dumps({"service": "pi-probe-discord-dashboard", "test_count": 1}), encoding="utf-8")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
            except PermissionError:
                self.skipTest("socket bind not permitted in this environment")
            process = Process(target=serve_interactive_dashboard, args=(str(dashboard_file), "127.0.0.1", port), daemon=True)
            process.start()
            try:
                time.sleep(0.5)
                health = urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3).read().decode("utf-8")
                status = json.loads(urlopen(f"http://127.0.0.1:{port}/status.json", timeout=3).read().decode("utf-8"))
                index = urlopen(f"http://127.0.0.1:{port}/", timeout=3).read().decode("utf-8")
                self.assertEqual(health.strip(), "ok")
                self.assertEqual(status["service"], "pi-probe-discord-dashboard")
                self.assertIn("dashboard", index)
            finally:
                process.terminate()
                process.join(timeout=2)

    def test_dashboard_server_exposes_read_only_data_endpoint_with_no_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = replace(make_config(base), interactive_dashboard_file=str(base / "dashboard" / "index.html"))
            dashboard_dir = Path(config.interactive_dashboard_file).parent
            dashboard_dir.mkdir(parents=True, exist_ok=True)
            Path(config.interactive_dashboard_file).write_text("<html><body>dashboard</body></html>", encoding="utf-8")
            Path(config.router_events_csv).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_json).parent.mkdir(parents=True, exist_ok=True)
            Path(config.nmap_inventory_json).write_text(
                json.dumps(
                    {
                        "scannedAt": "2026-06-06T10:15:00",
                        "network": "192.168.1.0/24",
                        "deviceCount": 1,
                        "devices": [
                            {
                                "id": "192.168.1.77",
                                "name": "Bambu Lab 3D Printer",
                                "hostname": "printer",
                                "ip": "192.168.1.77",
                                "vendor": "Bambu Lab",
                                "manufacturer": "Bambu Lab",
                                "deviceType": "3d_printer",
                                "identificationConfidence": "confirmed",
                                "identificationScore": 100,
                                "identificationReasons": ["TLS issuer contains BBL Technologies Co. Ltd"],
                                "deviceId": "22E8BJ5C1401474",
                                "displayEvidence": "Verified by Bambu device certificate",
                                "status": "up",
                                "category": "printer",
                                "categoryLabel": "3D Printer",
                                "accent": "rose",
                                "ports": [],
                                "openPorts": [],
                                "services": [],
                                "portCount": 0,
                                "lastSeen": "2026-06-06T10:15:00",
                            }
                        ],
                        "scanState": {
                            "lastScanStart": "2026-06-06T10:10:00",
                            "lastSuccessfulScan": "2026-06-06T10:15:00",
                            "lastFailedScan": "",
                            "lastScanDurationSeconds": 12.5,
                            "nextExpectedScan": "2026-06-06T16:10:00",
                            "configuredScanMinutes": 360,
                            "scanRunning": False,
                            "lastErrorSummary": "",
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch("pi_probe_discord.config.load_config", return_value=config):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.bind(("127.0.0.1", 0))
                        port = sock.getsockname()[1]
                except PermissionError:
                    self.skipTest("socket bind not permitted in this environment")
                process = Process(target=serve_interactive_dashboard, args=(str(config.interactive_dashboard_file), "127.0.0.1", port), daemon=True)
                process.start()
                try:
                    time.sleep(0.5)
                    response = urlopen(f"http://127.0.0.1:{port}/api/dashboard/data", timeout=3)
                    payload = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.headers.get("Cache-Control"), "no-store")
                    self.assertEqual(payload["inventory"]["deviceCount"], 1)
                    self.assertEqual(payload["devices"][0]["name"], "Bambu Lab 3D Printer")
                    self.assertNotIn("webhook_url", json.dumps(payload).lower())
                    self.assertNotIn("discord.invalid", json.dumps(payload))
                finally:
                    process.terminate()
                    process.join(timeout=2)

    def test_dashboard_server_requires_action_token_for_scan_but_not_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = replace(
                make_config(base),
                interactive_dashboard_file=str(base / "dashboard" / "index.html"),
                interactive_dashboard_api_token="secret-token",
            )
            dashboard_dir = Path(config.interactive_dashboard_file).parent
            dashboard_dir.mkdir(parents=True, exist_ok=True)
            Path(config.interactive_dashboard_file).write_text("<html><body>dashboard</body></html>", encoding="utf-8")
            with patch("pi_probe_discord.config.load_config", return_value=config):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.bind(("127.0.0.1", 0))
                        port = sock.getsockname()[1]
                except PermissionError:
                    self.skipTest("socket bind not permitted in this environment")
                process = Process(target=serve_interactive_dashboard, args=(str(config.interactive_dashboard_file), "127.0.0.1", port), daemon=True)
                process.start()
                try:
                    time.sleep(0.5)
                    data_response = urlopen(f"http://127.0.0.1:{port}/api/dashboard/data", timeout=3)
                    self.assertEqual(data_response.status, 200)
                    with self.assertRaises(HTTPError) as scan_error:
                        urlopen(
                            Request(
                                f"http://127.0.0.1:{port}/api/nmap/scan",
                                data=b"{}",
                                method="POST",
                            ),
                            timeout=3,
                        )
                    self.assertEqual(scan_error.exception.code, 401)
                    error_payload = json.loads(scan_error.exception.read().decode("utf-8"))
                    self.assertIn("Dashboard action token required", error_payload["message"])
                finally:
                    process.terminate()
                    process.join(timeout=2)

    def test_dashboard_server_returns_404_for_unknown_api_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = replace(make_config(base), interactive_dashboard_file=str(base / "dashboard" / "index.html"))
            dashboard_dir = Path(config.interactive_dashboard_file).parent
            dashboard_dir.mkdir(parents=True, exist_ok=True)
            Path(config.interactive_dashboard_file).write_text("<html><body>dashboard</body></html>", encoding="utf-8")
            with patch("pi_probe_discord.config.load_config", return_value=config):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.bind(("127.0.0.1", 0))
                        port = sock.getsockname()[1]
                except PermissionError:
                    self.skipTest("socket bind not permitted in this environment")
                process = Process(target=serve_interactive_dashboard, args=(str(config.interactive_dashboard_file), "127.0.0.1", port), daemon=True)
                process.start()
                try:
                    time.sleep(0.5)
                    with self.assertRaises(HTTPError) as error:
                        urlopen(
                            Request(
                                f"http://127.0.0.1:{port}/api/not-real",
                                data=b"{}",
                                method="POST",
                            ),
                            timeout=3,
                        )
                    self.assertEqual(error.exception.code, 404)
                finally:
                    process.terminate()
                    process.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
