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
DEFAULT_FIREWALL_LOG_PATHS = ["/var/log/ufw.log", "/var/log/kern.log", "/var/log/syslog"]


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
        log_file=os.environ.get("LOG_FILE", "/tmp/pihole-update-discord.log"),
        chart_file=os.environ.get("CHART_FILE", str(DEFAULT_CHART_PATH)),
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
    )
