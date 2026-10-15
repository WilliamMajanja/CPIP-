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
    VERSION = "7.0.0"

    _radio_silent = RADIO_SILENT
    _deadman_armed = False
    _deadman_last_rearm = time.time()
    _geofence: list[list[float]] = []
    _in_safe_zone = True
    _lock = threading.Lock()
    _silence_timer: threading.Timer | None = None
    _deadman_thread: threading.Thread | None = None
    _sweep_plan: dict[str, Any] | None = None

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        cls._load_geofence()
        if cls._deadman_thread is None or not cls._deadman_thread.is_alive():
            cls._deadman_thread = threading.Thread(target=cls._deadman_loop, daemon=True)
            cls._deadman_thread.start()
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
        duration = max(0, min(int(duration), 7 * 24 * 3600))
        with cls._lock:
            cls._radio_silent = True
            if cls._silence_timer:
                cls._silence_timer.cancel()
            if duration > 0:
                cls._silence_timer = threading.Timer(duration, cls._end_silence)
                cls._silence_timer.daemon = True
                cls._silence_timer.start()
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
    def set_deadman_timeout(cls, timeout: int) -> dict:
        global DEADMAN_TIMEOUT
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            return {"error": f"Invalid timeout: {timeout!r}"}
        if timeout <= 0:
            return {"error": "Timeout must be positive"}
        DEADMAN_TIMEOUT = timeout
        return {"status": "deadman_timeout_set", "timeout": DEADMAN_TIMEOUT}

    @classmethod
    def load_geofence_text(cls, text: str) -> dict:
        """Load a geofence from GPX/KML content supplied inline (RFC-0010)."""
        import xml.etree.ElementTree as ET

        coords: list[list[float]] = []
        try:
            root = ET.fromstring(text)
            ns = {"gpx": "http://www.topografix.com/GPX/1/1"}
            for trkpt in root.findall(".//gpx:trkpt", ns) or root.iter("trkpt"):
                lat, lon = trkpt.get("lat"), trkpt.get("lon")
                if lat is not None and lon is not None:
                    coords.append([float(lat), float(lon)])
            if not coords:
                for pm in root.iter():
                    tag = pm.tag.rsplit("}", 1)[-1]
                    if tag == "coordinates" and pm.text:
                        for triplet in pm.text.split():
                            parts = triplet.split(",")
                            if len(parts) >= 2:
                                coords.append([float(parts[1]), float(parts[0])])
        except ET.ParseError as e:
            return {"error": f"Invalid GPX/KML: {e}"}
        except (TypeError, ValueError) as e:
            return {"error": f"Invalid coordinates: {e}"}
        cls._geofence = coords
        logger.info("Geofence loaded: %d points", len(coords))
        return {"status": "geofence_loaded", "points": len(coords)}

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
    def _deadman_loop(cls):
        while True:
            time.sleep(1)
            if cls.deadman_check():
                cls.set_radio_silence(0)
                try:
                    from providers.deception import DeceptionProvider
                    DeceptionProvider.set_honeypot(True)
                except Exception as exc:
                    logger.debug("Dead-man deception activation failed: %s", exc)
                logger.critical("Dead-man timer expired; radio silence and deception mode activated")

    @classmethod
    def update_location(cls, lat: float, lon: float) -> dict:
        if len(cls._geofence) < 3:
            return {"error": "No polygon geofence is loaded"}
        inside = False
        points = cls._geofence
        j = len(points) - 1
        for i, (yi, xi) in enumerate(points):
            yj, xj = points[j]
            if ((yi > lat) != (yj > lat)) and (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi):
                inside = not inside
            j = i
        cls._in_safe_zone = inside
        return {"in_safe_zone": inside, "latitude": lat, "longitude": lon}

    @classmethod
    def plan_sweep(cls, bands: str | list[str]) -> dict:
        if isinstance(bands, str):
            bands = [b.strip() for b in bands.replace(" ", ",").split(",") if b.strip()]
        allowed = {"B2", "B4", "B5", "B12", "B13", "B66", "n71", "n78"}
        invalid = [b for b in bands if b not in allowed]
        if invalid:
            return {"error": f"Unsupported bands: {', '.join(invalid)}"}
        cls._sweep_plan = {"bands": list(dict.fromkeys(bands)), "created": time.time(),
                           "status": "planned; no radio scan started"}
        return dict(cls._sweep_plan)

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "radio_silent": cls._radio_silent,
            "deadman_armed": cls._deadman_armed,
            "deadman_remaining": max(0, DEADMAN_TIMEOUT - (time.time() - cls._deadman_last_rearm)) if cls._deadman_armed else 0,
            "geofence_points": len(cls._geofence),
            "in_safe_zone": cls._in_safe_zone,
            "sweep_plan": cls._sweep_plan,
        }
