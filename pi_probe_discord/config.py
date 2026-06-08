from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from .models import AppConfig


DEFAULT_SPEEDTEST_MINUTES = 60
DEFAULT_FULL_REPORT_SCHEDULE = "03:30"
DEFAULT_CONFIG_DIR = Path("/etc/pi-probe-discord")
DEFAULT_DATA_DIR = Path("/var/lib/pi-probe-discord")
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "pihole-update-discord.env"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "pi_probe_discord.db"
DEFAULT_CHART_PATH = DEFAULT_DATA_DIR / "speed_chart.png"
DEFAULT_FIREWALL_CHART_PATH = DEFAULT_DATA_DIR / "firewall_snapshot.png"
DEFAULT_INTERACTIVE_DASHBOARD_PATH = DEFAULT_DATA_DIR / "dashboard" / "index.html"
DEFAULT_ROUTER_EVENTS_CSV = DEFAULT_DATA_DIR / "events" / "router_events.csv"
DEFAULT_ROUTER_EVENTS_JSON = DEFAULT_DATA_DIR / "events" / "router_events.json"
DEFAULT_PIHOLE_HOURLY_CSV = DEFAULT_DATA_DIR / "pihole" / "pihole_hourly.csv"
DEFAULT_PIHOLE_FTL_DB_PATH = Path("/etc/pihole/pihole-FTL.db")
DEFAULT_FIREWALL_LOG_PATHS = ["/var/log/ufw.log", "/var/log/kern.log", "/var/log/syslog"]
DEFAULT_ROUTER_SNMP_LOG_PATH = "/var/log/snmptrapd.log"
DEFAULT_LOG_FILE = DEFAULT_DATA_DIR / "pihole-update-discord.log"


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_severity_map(name: str) -> dict[str, str]:
    raw = os.environ.get(name, "")
    parsed: dict[str, str] = {}
    for item in raw.split(","):
        pair = item.strip()
        if not pair or "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        sev = value.strip().lower()
        if sev in {"critical", "warning", "info"}:
            parsed[key.strip().lower()] = sev
    return parsed


def load_dotenv_style(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def validate_webhook_url(webhook_url: str) -> str:
    parsed = urlparse(webhook_url)
    if parsed.scheme != "https":
        raise RuntimeError("Webhook URL must use https.")
    if parsed.netloc not in {"discord.com", "ptb.discord.com", "canary.discord.com"}:
        raise RuntimeError("Webhook URL must point to an official Discord host.")
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 3 or path_parts[0] != "api" or path_parts[1] != "webhooks":
        raise RuntimeError("Webhook URL must match Discord webhook format.")
    if any(not part.strip() for part in path_parts[2:4]):
        raise RuntimeError("Webhook URL appears incomplete.")
    return webhook_url


def load_config(base_dir: Path | None = None, require_webhook: bool = True) -> AppConfig:
    root = base_dir or Path(__file__).resolve().parent.parent
    config_file = Path(os.environ.get("CONFIG_FILE", str(DEFAULT_CONFIG_FILE)))
    load_dotenv_style(config_file)

    webhook_url = os.environ.get("WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")
    if require_webhook and not webhook_url:
        raise RuntimeError(f"WEBHOOK_URL is not set. Export it or create {config_file}")
    if webhook_url:
        webhook_url = validate_webhook_url(webhook_url)

    return AppConfig(
        webhook_url=webhook_url or "",
        config_file=str(config_file),
        log_file=os.environ.get("LOG_FILE", str(DEFAULT_LOG_FILE)),
        chart_file=os.environ.get("CHART_FILE", str(DEFAULT_CHART_PATH)),
        firewall_chart_file=os.environ.get("PI_PROBE_FIREWALL_CHART_FILE", str(DEFAULT_FIREWALL_CHART_PATH)),
        dashboard_style=os.environ.get("PI_PROBE_DASHBOARD_STYLE", "standard").strip().lower() or "standard",
        interactive_dashboard_enabled=_env_bool("PI_PROBE_INTERACTIVE_DASHBOARD_ENABLED", False),
        interactive_dashboard_file=os.environ.get(
            "PI_PROBE_INTERACTIVE_DASHBOARD_FILE",
            str(DEFAULT_INTERACTIVE_DASHBOARD_PATH),
        ),
        interactive_dashboard_host=os.environ.get("PI_PROBE_INTERACTIVE_DASHBOARD_HOST", "127.0.0.1"),
        interactive_dashboard_port=max(1, int(os.environ.get("PI_PROBE_INTERACTIVE_DASHBOARD_PORT", "8088"))),
        interactive_dashboard_tls_enabled=_env_bool("PI_PROBE_INTERACTIVE_DASHBOARD_TLS_ENABLED", False),
        interactive_dashboard_tls_cert_file=os.environ.get(
            "PI_PROBE_INTERACTIVE_DASHBOARD_TLS_CERT_FILE",
            str(DEFAULT_CONFIG_DIR / "dashboard-cert.pem"),
        ),
        interactive_dashboard_tls_key_file=os.environ.get(
            "PI_PROBE_INTERACTIVE_DASHBOARD_TLS_KEY_FILE",
            str(DEFAULT_CONFIG_DIR / "dashboard-key.pem"),
        ),
        public_dashboard_url=os.environ.get("PI_PROBE_PUBLIC_DASHBOARD_URL", "").strip(),
        dashboard_link_label=os.environ.get("PI_PROBE_DASHBOARD_LINK_LABEL", "Open Interactive Dashboard").strip()
        or "Open Interactive Dashboard",
        outage_download_mbps=float(os.environ.get("PI_PROBE_OUTAGE_DOWNLOAD_MBPS", "50")),
        degraded_download_mbps=float(os.environ.get("PI_PROBE_DEGRADED_DOWNLOAD_MBPS", "250")),
        high_ping_ms=float(os.environ.get("PI_PROBE_HIGH_PING_MS", "20")),
        failed_test_is_outage=_env_bool("PI_PROBE_FAILED_TEST_IS_OUTAGE", True),
        heatmap_good_mbps=float(os.environ.get("PI_PROBE_HEATMAP_GOOD_MBPS", "320")),
        heatmap_warn_mbps=float(os.environ.get("PI_PROBE_HEATMAP_WARN_MBPS", "250")),
        router_events_csv=os.environ.get("PI_PROBE_ROUTER_EVENTS_CSV", str(DEFAULT_ROUTER_EVENTS_CSV)),
        router_events_json=os.environ.get("PI_PROBE_ROUTER_EVENTS_JSON", str(DEFAULT_ROUTER_EVENTS_JSON)),
        pihole_hourly_csv=os.environ.get("PI_PROBE_PIHOLE_HOURLY_CSV", str(DEFAULT_PIHOLE_HOURLY_CSV)),
        pihole_ftl_db_path=os.environ.get("PI_PROBE_PIHOLE_FTL_DB_PATH", str(DEFAULT_PIHOLE_FTL_DB_PATH)),
        db_path=os.environ.get("DB_PATH", str(DEFAULT_DB_PATH)),
        history_retention_days=int(os.environ.get("HISTORY_RETENTION_DAYS", "365")),
        request_timeout=int(os.environ.get("REQUEST_TIMEOUT", "30")),
        max_text_field_length=int(os.environ.get("MAX_TEXT_FIELD_LENGTH", "1200")),
        speedtest_schedule_minutes=int(os.environ.get("SPEEDTEST_SCHEDULE_MINUTES", str(DEFAULT_SPEEDTEST_MINUTES))),
        full_report_schedule=os.environ.get("FULL_REPORT_SCHEDULE", DEFAULT_FULL_REPORT_SCHEDULE),
        firewall_enabled=_env_bool("PI_PROBE_FIREWALL_ENABLED", True),
        firewall_window_hours=max(1, int(os.environ.get("PI_PROBE_FIREWALL_WINDOW_HOURS", "24"))),
        firewall_top_n=max(1, int(os.environ.get("PI_PROBE_FIREWALL_TOP_N", "5"))),
        firewall_noisy_source_threshold=max(1, int(os.environ.get("PI_PROBE_FIREWALL_NOISY_SOURCE_THRESHOLD", "10"))),
        firewall_include_allow=_env_bool("PI_PROBE_FIREWALL_INCLUDE_ALLOW", False),
        firewall_log_paths=[
            item.strip()
            for item in os.environ.get("PI_PROBE_FIREWALL_LOG_PATHS", ",".join(DEFAULT_FIREWALL_LOG_PATHS)).split(",")
            if item.strip()
        ],
        firewall_alert_enabled=_env_bool("PI_PROBE_FIREWALL_ALERT_ENABLED", True),
        firewall_alert_min_blocks=max(1, int(os.environ.get("PI_PROBE_FIREWALL_ALERT_MIN_BLOCKS", "80"))),
        firewall_alert_min_ssh_attempts=max(1, int(os.environ.get("PI_PROBE_FIREWALL_ALERT_MIN_SSH_ATTEMPTS", "20"))),
        firewall_alert_min_noisy_sources=max(1, int(os.environ.get("PI_PROBE_FIREWALL_ALERT_MIN_NOISY_SOURCES", "2"))),
        firewall_alert_cooldown_minutes=max(1, int(os.environ.get("PI_PROBE_FIREWALL_ALERT_COOLDOWN_MINUTES", "60"))),
        firewall_alert_state_file=os.environ.get(
            "PI_PROBE_FIREWALL_ALERT_STATE_FILE",
            str(DEFAULT_DATA_DIR / "firewall_alert_state.json"),
        ),
        router_snmp_enabled=_env_bool("PI_PROBE_ROUTER_SNMP_ENABLED", False),
        router_snmp_log_path=os.environ.get("PI_PROBE_ROUTER_SNMP_LOG_PATH", DEFAULT_ROUTER_SNMP_LOG_PATH),
        router_snmp_state_file=os.environ.get(
            "PI_PROBE_ROUTER_SNMP_STATE_FILE",
            str(DEFAULT_DATA_DIR / "router_snmp_ingest_state.json"),
        ),
        router_snmp_window_hours=max(1, int(os.environ.get("PI_PROBE_ROUTER_SNMP_WINDOW_HOURS", "24"))),
        router_snmp_top_n=max(1, int(os.environ.get("PI_PROBE_ROUTER_SNMP_TOP_N", "5"))),
        router_snmp_listener_enabled=_env_bool("PI_PROBE_ROUTER_SNMP_LISTENER_ENABLED", False),
        router_snmp_bind_host=os.environ.get("PI_PROBE_ROUTER_SNMP_BIND_HOST", "127.0.0.1"),
        router_snmp_bind_port=max(1, int(os.environ.get("PI_PROBE_ROUTER_SNMP_BIND_PORT", "9162"))),
        router_snmp_max_events_per_minute=max(
            1, int(os.environ.get("PI_PROBE_ROUTER_SNMP_MAX_EVENTS_PER_MINUTE", "120"))
        ),
        router_snmp_max_packet_bytes=max(
            256, int(os.environ.get("PI_PROBE_ROUTER_SNMP_MAX_PACKET_BYTES", "4096"))
        ),
        router_snmp_oid_severity_map=_env_severity_map("PI_PROBE_ROUTER_SNMP_OID_SEVERITY_MAP"),
    )
