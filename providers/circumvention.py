from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import secrets
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

CIRCUMVENTION_ENABLED = os.environ.get("CPIP_CIRCUMVENTION", "0") == "1"
CIRCUMVENTION_MODE = os.environ.get("CPIP_CIRCUMVENTION_MODE", "https")
CIRCUMVENTION_FRONT = os.environ.get("CPIP_CIRCUMVENTION_FRONT_DOMAIN", "cdn.cloudflare.com")
CIRCUMVENTION_DOH = os.environ.get("CPIP_CIRCUMVENTION_DOH", "1") == "1"

SUPPORTED_MODES = ["https", "dns", "quic", "meek", "snowflake", "obfs4"]


class CircumventionProvider(BaseProvider):
    TYPE = ProviderType.CIRCUMVENTION
    NAME = "circumvention"
    VERSION = "6.0.0"

    _active_mode = CIRCUMVENTION_MODE
    _running = False

    HTTP_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache",
        "Pragma": "no-cookie",
    }

    TLS_RECORD_SIZES = [512, 1024, 4096, 16384]

    @classmethod
    def is_available(cls) -> bool:
        return CIRCUMVENTION_ENABLED

    @classmethod
    def wrap_message(cls, data: bytes) -> bytes:
        mode = cls._active_mode
        if mode == "https":
            return cls._wrap_https(data)
        elif mode == "dns":
            return cls._wrap_dns(data)
        elif mode == "quic":
            return cls._wrap_quic(data)
        return data

    @classmethod
    def _wrap_https(cls, data: bytes) -> bytes:
        boundary = secrets.token_hex(8)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{secrets.token_hex(4)}.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        padded = cls._pad_message(body)
        http = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: {CIRCUMVENTION_FRONT}\r\n"
            f"Content-Length: {len(padded)}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        )
        for k, v in cls.HTTP_HEADERS.items():
            http += f"{k}: {v}\r\n"
        http += f"\r\n".encode()
        return http + padded

    @classmethod
    def _wrap_dns(cls, data: bytes) -> bytes:
        encoded = data.hex()
        domain = f"{encoded[:63]}.{CIRCUMVENTION_FRONT}"
        return json.dumps({"dns_query": domain, "type": "TXT"}).encode()

    @classmethod
    def _wrap_quic(cls, data: bytes) -> bytes:
        return cls._pad_message(data)

    @classmethod
    def _pad_message(cls, data: bytes) -> bytes:
        target = secrets.choice(cls.TLS_RECORD_SIZES)
        if len(data) < target:
            padding = secrets.token_bytes(target - len(data))
            return data + b"\x00" + padding
        return data

    @classmethod
    def set_mode(cls, mode: str) -> dict:
        if mode not in SUPPORTED_MODES:
            return {"error": f"Unsupported mode: {mode}. Choose: {SUPPORTED_MODES}"}
        cls._active_mode = mode
        return {"status": "mode_changed", "mode": mode}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": CIRCUMVENTION_ENABLED,
            "active_mode": cls._active_mode,
            "available_modes": SUPPORTED_MODES,
            "front_domain": CIRCUMVENTION_FRONT,
            "doh": CIRCUMVENTION_DOH,
        }
