from __future__ import annotations

import base64
import hashlib
import os
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from urllib3.exceptions import InsecureRequestWarning

from .config import load_router_webui_secrets
from .models import AppConfig

_LOGIN_PARMS_RE = re.compile(r'var\s+(\w+)="?([^";]+)"?;')
_TOKEN_RE = re.compile(r'var token="([^"]+)";')
_DEFAULT_STACK = "0,0,0,0,0,0"


def _normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9a-f]", "", value.lower())
    if len(compact) != 12:
        return ""
    return ":".join(compact[idx : idx + 2] for idx in range(0, 12, 2))


def _rsa_encrypt_raw_chunks(text: str, modulus_hex: str, exponent_hex: str, *, chunk_bytes: int = 64) -> str:
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    data = text.encode("utf-8")
    parts: list[str] = []
    for idx in range(0, len(data), chunk_bytes):
        chunk = data[idx : idx + chunk_bytes]
        message = int.from_bytes(chunk.ljust(chunk_bytes, b"\x00"), "big")
        encrypted = pow(message, exponent, modulus)
        parts.append(f"{encrypted:0{chunk_bytes * 2}x}")
    return "".join(parts)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_pinned_certificate_fingerprint(certificate_path: str) -> str:
    pem = Path(certificate_path).read_text(encoding="utf-8")
    return _sha256_hex(ssl.PEM_cert_to_DER_cert(pem))


def _parse_https_endpoint(base_url: str) -> tuple[str, int]:
    match = re.match(r"^https?://([^/:]+)(?::(\d+))?", base_url.strip())
    if match is None:
        raise RuntimeError(f"Could not parse router Web UI URL: {base_url}")
    return match.group(1), int(match.group(2) or 443)


def _fetch_peer_certificate_fingerprint(base_url: str) -> str:
    host, port = _parse_https_endpoint(base_url)
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=15) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return _sha256_hex(tls_sock.getpeercert(binary_form=True))


class _PinnedFingerprintAdapter(HTTPAdapter):
    def __init__(self, fingerprint: str, **kwargs: Any) -> None:
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs.setdefault("assert_fingerprint", self._fingerprint)
        pool_kwargs.setdefault("cert_reqs", ssl.CERT_NONE)
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs.setdefault("assert_fingerprint", self._fingerprint)
        proxy_kwargs.setdefault("cert_reqs", ssl.CERT_NONE)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _parse_object_response(payload: str, *, collection: bool) -> list[dict[str, str]] | dict[str, str]:
    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("["):
            end = line.find("]")
            if end < 0:
                continue
            stack = line[1:end]
            value = line[end + 1 :].strip()
            if stack == "error":
                if value and value != "0":
                    raise RuntimeError(f"Router Web UI CGI error {value}")
                current = None
                continue
            current = {"__stack": stack}
            items.append(current)
            continue
        if current is None:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
        else:
            current[line] = ""
    if collection:
        return items
    return items[0] if items else {}


@dataclass
class _RouterWebUiSession:
    base_url: str
    username: str
    password: str
    ca_file: str = ""

    def __post_init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        if self.ca_file:
            certificate_path = Path(self.ca_file)
            if not certificate_path.exists():
                raise RuntimeError(f"Router Web UI CA/certificate file not found: {self.ca_file}")
            fingerprint = _load_pinned_certificate_fingerprint(self.ca_file)
            if _fetch_peer_certificate_fingerprint(self.base_url) != fingerprint:
                raise RuntimeError("Router Web UI certificate pin mismatch.")
            self.session.mount(self.base_url, _PinnedFingerprintAdapter(fingerprint))
        self.headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": f"{self.base_url}/",
            "Origin": self.base_url,
        }
        self._aes_key = b""
        self._aes_iv = b""
        self._hash = ""
        self._seq = 0
        self._nn = ""
        self._ee = ""
        self._token = "0"

    def login(self) -> None:
        self.session.get(f"{self.base_url}/", headers=self.headers, timeout=15)
        parm_response = self.session.post(
            f"{self.base_url}/cgi/getParm?_={int(time.time() * 1000)}",
            headers=self.headers,
            timeout=15,
        )
        parm_response.raise_for_status()
        values = dict(_LOGIN_PARMS_RE.findall(parm_response.text))
        if not {"seq", "nn", "ee"}.issubset(values):
            raise RuntimeError("Router Web UI login parameters were not returned.")
        self._seq = int(values["seq"])
        self._nn = values["nn"]
        self._ee = values["ee"]
        self._hash = hashlib.md5((self.username + self.password).encode("utf-8")).hexdigest()
        seed = str(int(time.time() * 1000)) + str(random.randint(0, 999_999_999))
        self._aes_key = seed[:16].encode("utf-8")
        self._aes_iv = seed[::-1][:16].encode("utf-8")
        aes_key_string = f"key={self._aes_key.decode()}&iv={self._aes_iv.decode()}"
        login_plaintext = f"{self.username}\n{self.password}".encode("utf-8")
        login_data = base64.b64encode(
            AES.new(self._aes_key, AES.MODE_CBC, self._aes_iv).encrypt(pad(login_plaintext, 16))
        ).decode("ascii")
        login_sign = _rsa_encrypt_raw_chunks(
            f"{aes_key_string}&h={self._hash}&s={self._seq + len(login_data)}",
            self._nn,
            self._ee,
        )
        login_response = self.session.post(
            f"{self.base_url}/cgi/login?data={quote(login_data)}&sign={login_sign}&Action=1&LoginStatus=0&isMobile=0",
            headers=self.headers,
            timeout=15,
        )
        login_response.raise_for_status()
        if "$.ret=0" not in login_response.text:
            raise RuntimeError("Router Web UI login failed.")
        index_response = self.session.get(f"{self.base_url}/", headers=self.headers, timeout=15)
        index_response.raise_for_status()
        token_match = _TOKEN_RE.search(index_response.text)
        if token_match is None:
            raise RuntimeError("Router Web UI token was not found after login.")
        self._token = token_match.group(1)

    def _encrypt_body(self, text: str) -> tuple[str, str]:
        data = base64.b64encode(
            AES.new(self._aes_key, AES.MODE_CBC, self._aes_iv).encrypt(pad(text.encode("utf-8"), 16))
        ).decode("ascii")
        sign = _rsa_encrypt_raw_chunks(f"h={self._hash}&s={self._seq + len(data)}", self._nn, self._ee)
        return data, sign

    def _decrypt_body(self, text: str) -> str:
        raw = base64.b64decode(text)
        decrypted = AES.new(self._aes_key, AES.MODE_CBC, self._aes_iv).decrypt(raw)
        return unpad(decrypted, 16).decode("utf-8", errors="replace")

    def call(self, action: int, oid: str, attrs: list[str], *, collection: bool) -> list[dict[str, str]] | dict[str, str]:
        attr_block = "".join(f"{attr}\r\n" for attr in attrs)
        body = f"{action}\r\n[{oid}#{_DEFAULT_STACK}#{_DEFAULT_STACK}]0,{len(attrs)}\r\n{attr_block}"
        enc_data, enc_sign = self._encrypt_body(body)
        headers = dict(self.headers)
        headers["TokenID"] = self._token
        response = self.session.post(
            f"{self.base_url}/cgi_gdpr?{action}",
            headers=headers,
            data=f"sign={enc_sign}\r\ndata={enc_data}\r\n",
            timeout=15,
        )
        response.raise_for_status()
        return _parse_object_response(self._decrypt_body(response.text), collection=collection)


def collect_router_webui_snapshot(config: AppConfig, now_iso: str) -> dict[str, Any]:
    if not config.router_webui_enabled:
        return {
            "generatedAt": now_iso,
            "enabled": False,
            "available": False,
            "source": "router-webui-lan-host-entry",
            "nodes": [],
            "hostTable": [],
            "errors": [],
            "notes": [],
        }
    secrets = load_router_webui_secrets(config)
    session = _RouterWebUiSession(
        base_url=config.router_webui_url.rstrip("/"),
        username=secrets["username"],
        password=secrets["password"],
        ca_file=config.router_webui_ca_file.strip(),
    )
    session.login()
    info = session.call(1, "IGD_DEV_INFO", ["modelName", "description", "X_TP_IsFD"], collection=False)
    current_user = session.call(1, "CURRENT_USER", ["userName", "userSetting", "userRole"], collection=False)
    host_entries = session.call(5, "LAN_HOST_ENTRY", ["hostName", "IPAddress", "MACAddress", "active"], collection=True)

    router_ip = re.sub(r"^https?://", "", config.router_webui_url.rstrip("/")).split("/", 1)[0].split(":", 1)[0]
    router_name = str(info.get("modelName") or "Router").strip() or "Router"
    hosts: list[dict[str, Any]] = []
    for entry in host_entries:
        ip = str(entry.get("IPAddress") or "").strip()
        mac = _normalize_mac(str(entry.get("MACAddress") or ""))
        if not ip and not mac:
            continue
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostName": str(entry.get("hostName") or "").strip(),
                "active": str(entry.get("active") or "").strip() == "1",
                "sourceNodeId": "router-webui",
                "sourceManagementIp": router_ip,
                "sourceNodeName": router_name,
                "sourceNodeRole": "router",
            }
        )
    return {
        "generatedAt": now_iso,
        "enabled": True,
        "available": bool(hosts),
        "source": "router-webui-lan-host-entry",
        "nodes": [
            {
                "id": "router-webui",
                "name": router_name,
                "host": router_ip,
                "managementIp": router_ip,
                "role": "router",
                "location": "",
                "ok": bool(hosts),
                "errors": [],
                "interfaces": [],
                "basePorts": [],
                "fdb": [],
                "depth": 0,
                "webUiHostCount": len(hosts),
                "currentUser": str(current_user.get("userName") or "").strip(),
            }
        ],
        "hostTable": hosts,
        "errors": [],
        "notes": [
            "Router Web UI host table fallback in use.",
            "Router Web UI host data does not expose downstream uplink relationships.",
        ],
    }
