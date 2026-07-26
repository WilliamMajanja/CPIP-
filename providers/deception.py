from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

DECEPTION_ENABLED = os.environ.get("CPIP_DECEPTION", "0") == "1"
CHAFF_INTENSITY = os.environ.get("CPIP_DECEPTION_CHAFF_INTENSITY", "medium")
HONEYPOT_COUNT = int(os.environ.get("CPIP_DECEPTION_HONEYPOT_COUNT", "3"))


class DeceptionProvider(BaseProvider):
    TYPE = ProviderType.DECEPTION
    NAME = "deception"
    VERSION = "6.0.0"

    _honeypots: list[dict] = []
    _honeypot_connections: list[dict] = []
    _chaff_enabled = DECEPTION_ENABLED
    _running = False
    _thread: threading.Thread | None = None
    _lock = threading.Lock()

    FAKE_DEVICE_MODELS = [
        "iPhone17,3", "Pixel 11 Pro", "Galaxy S26", "Fairphone 6",
    ]

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._spawn_honeypots()
        if DECEPTION_ENABLED:
            cls._thread = threading.Thread(target=cls._chaff_loop, daemon=True)
            cls._thread.start()
        logger.info("DeceptionProvider started with %d honeypots", HONEYPOT_COUNT)

    @classmethod
    def _spawn_honeypots(cls):
        for i in range(HONEYPOT_COUNT):
            model = secrets.choice(cls.FAKE_DEVICE_MODELS)
            cls._honeypots.append({
                "id": f"honeypot_{i}_{secrets.token_hex(4)}",
                "model": model,
                "uptime_h": secrets.randbelow(720) + 1,
                "peers_known": secrets.randbelow(10),
                "created": time.time(),
            })

    @classmethod
    def _chaff_loop(cls):
        while cls._running:
            try:
                cls._generate_chaff()
            except Exception:
                pass
            interval = {"low": 60, "medium": 30, "high": 10}.get(CHAFF_INTENSITY, 30)
            time.sleep(interval)

    @classmethod
    def _generate_chaff(cls):
        intensity = {"low": 1, "medium": 3, "high": 6}.get(CHAFF_INTENSITY, 3)
        for _ in range(intensity):
            topic = secrets.choice(["coffee", "tea", "weather", "network", "mesh", "radio", "crypto", "routing"])
            msg = {
                "type": "chaff",
                "topic": topic,
                "payload_len": secrets.randbelow(256) + 64,
                "timestamp": time.time(),
                "from": secrets.choice(cls._honeypots)["id"] if cls._honeypots else "unknown",
            }
            with cls._lock:
                pass

    @classmethod
    def log_connection(cls, addr: str, fingerprint: str):
        with cls._lock:
            cls._honeypot_connections.append({
                "time": time.time(),
                "addr": addr,
                "fingerprint": fingerprint,
                "honeypot_id": secrets.choice(cls._honeypots)["id"] if cls._honeypots else "unknown",
            })

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        with cls._lock:
            return {
                "enabled": DECEPTION_ENABLED,
                "chaff_intensity": CHAFF_INTENSITY,
                "honeypots_active": len(cls._honeypots),
                "honeypot_connections": len(cls._honeypot_connections),
                "recent_connections": cls._honeypot_connections[-5:] if cls._honeypot_connections else [],
            }
