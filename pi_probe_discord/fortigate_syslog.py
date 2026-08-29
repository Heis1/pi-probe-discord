from __future__ import annotations

import socket
from datetime import datetime
from pathlib import Path


def run_fortigate_syslog_receiver(config: object) -> int:
    allowed = set(getattr(config, "fortigate_syslog_allowed_sources", []))
    log_file = Path(str(getattr(config, "fortigate_syslog_log_file")))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((str(getattr(config, "fortigate_syslog_bind_host")), int(getattr(config, "fortigate_syslog_port"))))
        while True:
            payload, address = server.recvfrom(16384)
            if allowed and address[0] not in allowed:
                continue
            message = payload.decode("utf-8", errors="replace").replace("\x00", " ").replace("\n", " ").strip()
            if message:
                with log_file.open("a", encoding="utf-8") as output:
                    output.write(f"{datetime.now().astimezone().isoformat()} source={address[0]} {message}\n")
