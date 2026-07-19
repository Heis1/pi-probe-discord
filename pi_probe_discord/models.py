from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AppConfig:
    webhook_url: str
    config_file: str
    log_file: str
    chart_file: str
    firewall_chart_file: str
    dashboard_style: str
    interactive_dashboard_enabled: bool
    interactive_dashboard_file: str
    interactive_dashboard_host: str
    interactive_dashboard_port: int
    interactive_dashboard_tls_enabled: bool
    interactive_dashboard_tls_cert_file: str
    interactive_dashboard_tls_key_file: str
    interactive_dashboard_api_token: str
    dashboard_refresh_seconds: int
    public_dashboard_url: str
    dashboard_link_label: str
    outage_download_mbps: float
    degraded_download_mbps: float
    high_ping_ms: float
    failed_test_is_outage: bool
    heatmap_good_mbps: float
    heatmap_warn_mbps: float
    router_events_csv: str
    router_events_json: str
    pihole_hourly_csv: str
    pihole_ftl_db_path: str
    nmap_inventory_xml: str
    nmap_inventory_json: str
    nmap_events_json: str
    nmap_overrides_json: str
    nmap_state_json: str
    nmap_targets: str
    nmap_arguments: str
    nmap_scan_minutes: int
    db_path: str
    history_retention_days: int
    request_timeout: int
    max_text_field_length: int
    speedtest_schedule_minutes: int
    full_report_schedule: str
    firewall_enabled: bool
    firewall_window_hours: int
    firewall_top_n: int
    firewall_noisy_source_threshold: int
    firewall_include_allow: bool
    firewall_log_paths: list[str]
    firewall_alert_enabled: bool
    firewall_alert_min_blocks: int
    firewall_alert_min_ssh_attempts: int
    firewall_alert_min_noisy_sources: int
    firewall_alert_cooldown_minutes: int
    firewall_alert_state_file: str
    router_snmp_enabled: bool
    router_snmp_log_path: str
    router_snmp_state_file: str
    router_snmp_window_hours: int
    router_snmp_top_n: int
    router_snmp_listener_enabled: bool
    router_snmp_bind_host: str
    router_snmp_bind_port: int
    router_snmp_max_events_per_minute: int
    router_snmp_max_packet_bytes: int
    router_snmp_oid_severity_map: dict[str, str]
    topology_enabled: bool
    topology_nodes_json: str
    topology_cache_json: str
    topology_refresh_minutes: int
    topology_snmpwalk_bin: str
    topology_snmp_timeout_seconds: int
    router_webui_enabled: bool
    router_webui_url: str
    router_webui_secret_file: str
    router_webui_ca_file: str
    keepalive_enabled: bool
    keepalive_devices_json: str
    keepalive_state_json: str
    keepalive_timeout_seconds: int
    smtp_log_enabled: bool
    smtp_log_bind_host: str
    smtp_log_port: int
    smtp_log_directory: str
    discord_bot_token: str
    discord_report_channel_id: int
    discord_command_guild_id: int
    discord_allowed_user_ids: list[int]


@dataclass
class DeviceOverride:
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    name: str = ""
    category: str = ""
    hidden: bool | None = None
    role: str = ""
    location: str = ""
    uplink_ip: str = ""


@dataclass
class UpdateResult:
    ok: bool
    summary: str
    error: str = ""
    packages: list[str] = field(default_factory=list)


@dataclass
class PiholeResult:
    service_status: str = "Unknown"
    blocking_status: str = "Unknown"
    gravity_age: str = "Unavailable"
    blocklist_count: str = "Unavailable"
    update_status: str = "Unknown"
    warnings: list[str] = field(default_factory=list)


@dataclass
class SpeedResult:
    ok: bool
    summary: str
    download_mbps: float | None = None
    upload_mbps: float | None = None
    ping_ms: float | None = None
    chart_generated: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class RunRecord:
    recorded_at: datetime
    hostname: str
    update_ok: bool
    update_summary: str
    update_error: str
    pihole_service_status: str
    pihole_blocking_status: str
    pihole_gravity_age: str
    pihole_blocklist_count: str
    pihole_warnings: str
    speed_ok: bool
    speed_summary: str
    download_mbps: float | None
    upload_mbps: float | None
    ping_ms: float | None
    speed_warnings: str


@dataclass
class RouterSnapshot:
    enabled: bool
    ingest_source: str
    ingested_events: int
    window_hours: int
    recent_events: int
    link_down_events: int
    auth_fail_events: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_trap_oids: list[tuple[str, int]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
