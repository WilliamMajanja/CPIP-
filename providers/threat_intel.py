from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

SHARING_ENABLED = os.environ.get("CPIP_THREAT_SHARING", "0") == "1"
REQUIRE_PEERS = int(os.environ.get("CPIP_THREAT_REQUIRE_PEERS", "3"))
GOSSIP_INTERVAL = int(os.environ.get("CPIP_THREAT_GOSSIP_INTERVAL", "60"))

SHARING_SALT = os.environ.get("CPIP_THREAT_SALT", "cpip-v6-default-salt")
CPIP_THREAT_DHT_BOOTSTRAP = os.environ.get("CPIP_THREAT_DHT_BOOTSTRAP", "")


class ThreatIntelProvider(BaseProvider):
    TYPE = ProviderType.INTELLIGENCE
    NAME = "threat_intel"
    VERSION = "7.0.0"

    _lock = threading.Lock()
    _sightings: dict[str, list[dict]] = {}
    _peer_reports: dict[str, list[dict]] = {}
    _alerts: list[dict] = []

    @classmethod
    def set_sharing_enabled(cls, enabled: bool) -> dict:
        """Toggle local sharing at runtime; local sightings remain available."""
        global SHARING_ENABLED
        SHARING_ENABLED = bool(enabled)
        return {"status": "sharing_updated", "enabled": SHARING_ENABLED}

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def anonymize(cls, cell_id: str, mcc: str, mnc: str) -> str:
        raw = f"{cell_id}:{mcc}:{mnc}:{SHARING_SALT}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @classmethod
    def report_sighting(cls, cell_id: str, mcc: str, mnc: str, lac: str,
                        signal: float, lat: float, lon: float,
                        threat_type: str = "unknown", confidence: float = 0.5):
        if not SHARING_ENABLED:
            return
        anon_id = cls.anonymize(cell_id, mcc, mnc)
        lat_r = round(lat, 1)
        lon_r = round(lon, 1)
        entry = {
            "cell_hash": anon_id,
            "mcc": mcc, "mnc": mnc,
            "lat": lat_r, "lon": lon_r,
            "signal": signal,
            "threat_type": threat_type,
            "confidence": confidence,
            "timestamp": int(time.time()),
        }
        with cls._lock:
            if anon_id not in cls._sightings:
                cls._sightings[anon_id] = []
            cls._sightings[anon_id].append(entry)
            if len(cls._sightings[anon_id]) > 100:
                cls._sightings[anon_id] = cls._sightings[anon_id][-100:]
            cls._check_community_alert(anon_id)

    @classmethod
    def ingest_peer_report(cls, peer_id: str, report: dict):
        with cls._lock:
            if peer_id not in cls._peer_reports:
                cls._peer_reports[peer_id] = []
            cls._peer_reports[peer_id].append(report)
            if len(cls._peer_reports[peer_id]) > 50:
                cls._peer_reports[peer_id] = cls._peer_reports[peer_id][-50:]

    @classmethod
    def _check_community_alert(cls, anon_id: str):
        sightings = cls._sightings.get(anon_id, [])
        unique_sources = set(
            (s["lat"], s["lon"]) for s in sightings[-50:]
            if s["timestamp"] > time.time() - 3600
        )
        if len(unique_sources) >= REQUIRE_PEERS:
            alert_msg = f"Community alert: {anon_id} seen by {len(unique_sources)} nodes"
            cls._alerts.append({
                "time": time.time(),
                "message": alert_msg,
                "cell_hash": anon_id,
                "sources": len(unique_sources),
                "confidence": min(1.0, len(unique_sources) / REQUIRE_PEERS),
            })
            logger.warning("THREAT INTEL: %s", alert_msg)

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        with cls._lock:
            return {
                "enabled": SHARING_ENABLED,
                "sharing_enabled": SHARING_ENABLED,
                "bootstrap_nodes": [n.strip() for n in CPIP_THREAT_DHT_BOOTSTRAP.split(",") if n.strip()],
                "sightings_count": sum(len(v) for v in cls._sightings.values()),
                "unique_cells": len(cls._sightings),
                "peer_reports": sum(len(v) for v in cls._peer_reports.values()),
                "alerts": cls._alerts[-10:] if cls._alerts else [],
            }

    @classmethod
    def get_map_data(cls) -> list[dict]:
        with cls._lock:
            features = []
            for anon_id, sightings in cls._sightings.items():
                recent = [s for s in sightings if s["timestamp"] > time.time() - 86400]
                if recent:
                    avg_lat = sum(s["lat"] for s in recent) / len(recent)
                    avg_lon = sum(s["lon"] for s in recent) / len(recent)
                    features.append({
                        "cell_hash": anon_id,
                        "lat": avg_lat, "lon": avg_lon,
                        "count": len(recent),
                        "last_seen": recent[-1]["timestamp"],
                        "threat_type": recent[-1]["threat_type"],
                    })
            return features


class GlobalIntelProvider(ThreatIntelProvider):
    NAME = "global_intel"

    @classmethod
    def risk_score(cls, mcc: str, mnc: str) -> dict:
        with cls._lock:
            matching = []
            for anon_id, sightings in cls._sightings.items():
                for s in sightings:
                    if s.get("mcc") == mcc and s.get("mnc") == mnc:
                        matching.append(s)
            total = len(matching)
            threats = sum(1 for s in matching if s.get("confidence", 0) > 0.5)
            return {
                "mcc": mcc,
                "mnc": mnc,
                "total_sightings": total,
                "threat_sightings": threats,
                "risk_score": min(1.0, threats / max(total, 1)) if total > 0 else 0,
                "risk_label": "HIGH" if threats > 10 else "MEDIUM" if threats > 3 else "LOW" if threats > 0 else "NONE",
            }

    @classmethod
    def verify_cell(cls, cell_id: str) -> dict:
        """Verify a cell against community sightings (RFC-0007/0026).

        Accepts a raw cell_id, an anonymized cell_hash, or a composite
        'cell_id:mcc:mnc' string; the composite form is hashed with the
        same salted scheme used for sharing before lookup.
        """
        parts = cell_id.split(":")
        if len(parts) == 3:
            anon = cls.anonymize(parts[0], parts[1], parts[2])
        else:
            anon = cell_id
        with cls._lock:
            sightings = cls._sightings.get(anon, [])
            alerts = [a for a in cls._alerts if a.get("cell_hash") == anon]
            recent = [s for s in sightings if s["timestamp"] > time.time() - 86400]
            return {
                "cell": cell_id,
                "cell_hash": anon,
                "known": bool(sightings),
                "sightings_24h": len(recent),
                "community_alert": alerts[-1] if alerts else None,
                "verdict": ("KNOWN_THREAT" if len(recent) >= REQUIRE_PEERS
                            else "KNOWN" if sightings else "UNKNOWN"),
            }
