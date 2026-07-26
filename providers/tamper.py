from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

TAMPER_CASE_PIN = int(os.environ.get("CPIP_TAMPER_CASE_PIN", "16"))
TAMPER_USB_MONITOR = os.environ.get("CPIP_TAMPER_USB_MONITOR", "1") == "1"
TAMPER_RTC_CHECK = os.environ.get("CPIP_TAMPER_RTC_CHECK", "1") == "1"


class TamperProvider(BaseProvider):
    TYPE = ProviderType.SECURITY
    NAME = "tamper"
    VERSION = "6.0.0"

    _events: list[dict] = []
    _lock = threading.Lock()
    _last_rtc_time = time.time()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        if TAMPER_RTC_CHECK:
            cls._last_rtc_time = time.time()
        logger.info("TamperProvider started")

    @classmethod
    def report_event(cls, event_type: str, severity: str, message: str):
        entry = {
            "time": time.time(),
            "type": event_type,
            "severity": severity,
            "message": message,
            "hash": hashlib.sha256(f"{time.time()}:{event_type}:{message}".encode()).hexdigest()[:16],
        }
        with cls._lock:
            cls._events.append(entry)
            if len(cls._events) > 100:
                cls._events = cls._events[-100:]
        if severity in ("critical", "high"):
            logger.warning("TAMPER: %s — %s", event_type, message)

    @classmethod
    def check_rtc(cls) -> dict | None:
        if not TAMPER_RTC_CHECK:
            return None
        try:
            now = time.time()
            drift = now - cls._last_rtc_time
            cls._last_rtc_time = now
            if drift < -60:
                cls.report_event("rtc_rollback", "critical",
                                 f"RTC rolled back by {-drift:.0f}s (possible forensic tamper)")
                return {"rtc_rollback": True, "drift_s": drift}
            if drift > 3600:
                cls.report_event("rtc_gap", "medium",
                                 f"Time gap of {drift:.0f}s detected")
                return {"rtc_gap": True, "drift_s": drift}
        except Exception:
            pass
        return None

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        with cls._lock:
            return {
                "case_pin": TAMPER_CASE_PIN,
                "usb_monitor": TAMPER_USB_MONITOR,
                "rtc_check": TAMPER_RTC_CHECK,
                "events_total": len(cls._events),
                "recent": cls._events[-10:] if cls._events else [],
            }

    @classmethod
    def get_log(cls) -> list[dict]:
        with cls._lock:
            return list(cls._events)
