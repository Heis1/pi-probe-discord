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
    )
