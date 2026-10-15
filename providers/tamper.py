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
    VERSION = "7.0.0"

    _events: list[dict] = []
    _lock = threading.Lock()
    _running = False
    _thread: threading.Thread | None = None
    _last_wall_time = time.time()
    _last_monotonic = time.monotonic()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._last_wall_time = time.time()
        cls._last_monotonic = time.monotonic()
        cls._thread = threading.Thread(target=cls._monitor_loop, daemon=True)
        cls._thread.start()
        logger.info("TamperProvider started")

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _monitor_loop(cls):
        while cls._running:
            try:
                cls.check_rtc()
            except Exception as exc:
                logger.debug("Tamper monitor: %s", exc)
            time.sleep(10)

    @classmethod
    def report_event(cls, event_type: str, severity: str, message: str):
        with cls._lock:
            previous = cls._events[-1]["hash"] if cls._events else "0" * 64
            entry = {
                "time": time.time(),
                "type": event_type,
                "severity": severity,
                "message": message,
                "previous_hash": previous,
            }
            entry["hash"] = hashlib.sha256(
                json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            cls._events.append(entry)
        if severity in ("critical", "high"):
            logger.warning("TAMPER: %s — %s", event_type, message)
        return entry

    @classmethod
    def check_rtc(cls) -> dict | None:
        if not TAMPER_RTC_CHECK:
            return None
        try:
            now_wall = time.time()
            now_mono = time.monotonic()
            wall_delta = now_wall - cls._last_wall_time
            mono_delta = now_mono - cls._last_monotonic
            drift = wall_delta - mono_delta
            cls._last_wall_time = now_wall
            cls._last_monotonic = now_mono
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
                "running": cls._running,
                "events_total": len(cls._events),
                "recent": cls._events[-10:] if cls._events else [],
            }

    @classmethod
    def get_log(cls) -> list[dict]:
        with cls._lock:
            return list(cls._events)
