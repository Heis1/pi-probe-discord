from __future__ import annotations

import json
import base64
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def _append_event(config: Any, envelope: Any) -> None:
    raw = envelope.content.encode("utf-8", errors="replace") if isinstance(envelope.content, str) else bytes(envelope.content)
    mailbox = Path(config.smtp_log_directory)
    mailbox.mkdir(parents=True, exist_ok=True)
    received_at = datetime.now().astimezone()
    raw_path = mailbox / f"router-log-{received_at.strftime('%Y%m%dT%H%M%S%f')}.eml"
    raw_path.write_bytes(raw)
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(message.get("Subject", "Router mail log"))
    text_parts = [part.get_content() for part in message.walk() if part.get_content_type() == "text/plain" and not part.get_filename()]
    attachments: list[str] = []
    for part in message.iter_attachments():
        data = part.get_payload(decode=True) or b""
        # AX1800 mail logs are encoded once by MIME and once by its webMail exporter.
        try:
            data = base64.b64decode(b"".join(data.split()), validate=True)
        except Exception:
            pass
        filename = part.get_filename() or "router-log.txt"
        attachment_path = mailbox / f"{raw_path.stem}-{filename}"
        attachment_path.write_bytes(data)
        attachments.append(data.decode(part.get_content_charset() or "utf-8", errors="replace"))
    body = "\n".join([*text_parts, *attachments]).strip()
    path = Path(config.router_events_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = []
    events = raw if isinstance(raw, list) else raw.get("events", []) if isinstance(raw, dict) else []
    events.append({
        "timestamp": received_at.isoformat(),
        "event_type": "router_mail_log",
        "message": f"{subject}: {body[:900]}",
        "severity": "warning" if any(word in body.lower() for word in ("error", "fail", "down", "reboot")) else "info",
        "source": envelope.mail_from or "router-mail",
    })
    path.write_text(json.dumps(events[-500:], indent=2), encoding="utf-8")


def run_smtp_log_receiver(config: Any) -> int:
    try:
        from aiosmtpd.controller import Controller
    except ImportError as exc:
        raise RuntimeError("SMTP log receiver requires python3-aiosmtpd.") from exc

    class Handler:
        async def handle_DATA(self, server, session, envelope):
            _append_event(config, envelope)
            return "250 Router log accepted"

    controller = Controller(Handler(), hostname=config.smtp_log_bind_host, port=config.smtp_log_port)
    controller.start()
    try:
        import time
        while True:
            time.sleep(3600)
    finally:
        controller.stop()
