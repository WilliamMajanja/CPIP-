from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import secrets
import threading
import time
import re
import base64
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
    VERSION = "7.0.0"

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
        raise NotImplementedError(f"Transport mode {mode!r} requires an external pluggable-transport backend")

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
        return http.encode() + b"\r\n" + padded

    @classmethod
    def _wrap_dns(cls, data: bytes) -> bytes:
        encoded = base64.b32encode(data).decode("ascii").rstrip("=").lower()
        labels = [encoded[i:i + 50] for i in range(0, len(encoded), 50)] or ["0"]
        queries = [f"{index:x}-{label}.{CIRCUMVENTION_FRONT}"
                   for index, label in enumerate(labels)]
        return json.dumps({"dns_queries": queries, "type": "TXT",
                           "encoding": "base32", "count": len(queries)}).encode()

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
    def set_front_domain(cls, domain: str) -> dict:
        """Set the domain-fronting target (RFC-0023)."""
        global CIRCUMVENTION_FRONT
        domain = str(domain or "").strip().lower()
        if not domain or len(domain) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain
        ):
            return {"error": f"Invalid front domain: {domain}"}
        CIRCUMVENTION_FRONT = domain
        logger.info("Circumvention front domain set to %s", domain)
        return {"status": "front_domain_set", "front_domain": CIRCUMVENTION_FRONT}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": CIRCUMVENTION_ENABLED,
            "active_mode": cls._active_mode,
            "available_modes": SUPPORTED_MODES,
            "front_domain": CIRCUMVENTION_FRONT,
            "doh": CIRCUMVENTION_DOH,
        }
