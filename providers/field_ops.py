from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

RADIO_SILENT = os.environ.get("CPIP_FIELD_RADIO_SILENT", "0") == "1"
DEADMAN_TIMEOUT = int(os.environ.get("CPIP_FIELD_DEADMAN_TIMEOUT", "86400"))
GEOFENCE_PATH = os.environ.get("CPIP_FIELD_GEOFENCE", "")


class FieldOpsProvider(BaseProvider):
    TYPE = ProviderType.SECURITY
    NAME = "field_ops"
    VERSION = "6.0.3"

    _radio_silent = RADIO_SILENT
    _deadman_armed = False
    _deadman_last_rearm = time.time()
    _geofence: list[list[float]] = []
    _in_safe_zone = True
    _lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        cls._load_geofence()
        if cls._radio_silent:
            logger.info("FieldOps: starting in RADIO SILENCE mode")

    @classmethod
    def _load_geofence(cls):
        if not GEOFENCE_PATH:
            return
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(GEOFENCE_PATH)
            ns = {"gpx": "http://www.topografix.com/GPX/1/1"}
            coords = []
            for trkpt in tree.findall(".//gpx:trkpt", ns):
                lat = float(trkpt.get("lat"))
                lon = float(trkpt.get("lon"))
                coords.append([lat, lon])
            if coords:
                cls._geofence = coords
                logger.info("Geofence loaded: %d points", len(coords))
        except Exception as e:
            logger.debug("Geofence load error: %s", e)

    @classmethod
    def set_radio_silence(cls, duration: int = 0) -> dict:
        with cls._lock:
            cls._radio_silent = True
            if duration > 0:
                threading.Timer(duration, cls._end_silence).start()
        return {"status": "radio_silence", "duration": duration}

    @classmethod
    def _end_silence(cls):
        with cls._lock:
            cls._radio_silent = False
        logger.info("Radio silence ended")

    @classmethod
    def is_radio_silent(cls) -> bool:
        return cls._radio_silent

    @classmethod
    def deadman_arm(cls) -> dict:
        cls._deadman_armed = True
        cls._deadman_last_rearm = time.time()
        return {"status": "armed", "timeout": DEADMAN_TIMEOUT}

    @classmethod
    def deadman_disarm(cls) -> dict:
        cls._deadman_armed = False
        return {"status": "disarmed"}

    @classmethod
    def deadman_rearm(cls) -> dict:
        cls._deadman_last_rearm = time.time()
        return {"status": "rearmed"}

    @classmethod
    def deadman_check(cls) -> bool:
        if not cls._deadman_armed:
            return False
        if time.time() - cls._deadman_last_rearm > DEADMAN_TIMEOUT:
            logger.critical("DEADMAN TRIGGERED: no re-arm within %ds", DEADMAN_TIMEOUT)
            cls._deadman_armed = False
            return True
        return False

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "radio_silent": cls._radio_silent,
            "deadman_armed": cls._deadman_armed,
            "deadman_remaining": max(0, DEADMAN_TIMEOUT - (time.time() - cls._deadman_last_rearm)) if cls._deadman_armed else 0,
            "geofence_points": len(cls._geofence),
            "in_safe_zone": cls._in_safe_zone,
        }
