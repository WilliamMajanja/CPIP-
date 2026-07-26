from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

SCORER_MODE = os.environ.get("CPIP_SCORER_MODE", "heuristic")
SCORER_TEMPORAL_WINDOW = int(os.environ.get("CPIP_SCORER_TEMPORAL_WINDOW", "60"))
SCORER_PAIR_BONUS = float(os.environ.get("CPIP_SCORER_PAIR_BONUS", "0.25"))
SCORER_BASELINE_DAYS = int(os.environ.get("CPIP_SCORER_BASELINE_DAYS", "7"))

THREAT_LABELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Scorer(BaseProvider):
    TYPE = ProviderType.SCORER
    NAME = "scorer"
    VERSION = "6.0.0"

    _events: list[dict[str, Any]] = []
    _lock = threading.Lock()
    _current_score = 0.0
    _score_history: list[dict] = []
    _ml_model = None

    # Heuristic weights (0.0-1.0)
    WEIGHTS = {
        "cellular_ta_zero": 0.8,
        "cellular_rat_downgrade": 0.7,
        "cellular_signal_jump": 0.5,
        "cellular_stationary_change": 0.6,
        "cellular_2g": 0.7,
        "sdr_phantom_tower": 0.8,
        "sdr_jammer": 0.9,
        "sensor_faraday": 0.9,
        "sensor_ultrasonic": 0.95,
        "sensor_gps_spoof": 0.85,
        "ss7_location_leak": 0.7,
        "ss7_sms_redirect": 0.75,
        "power_drain": 0.4,
        "tamper_case_open": 0.6,
        "mesh_peer_report": 0.5,
        "mesh_node_disappeared": 0.6,
    }

    PAIR_SYNERGY = [
        ("cellular_ta_zero", "cellular_stationary_change", 0.3),
        ("cellular_rat_downgrade", "cellular_2g", 0.2),
        ("cellular_signal_jump", "sdr_phantom_tower", 0.25),
        ("sensor_faraday", "cellular_stationary_change", 0.35),
        ("cellular_rat_downgrade", "sdr_jammer", 0.2),
        ("ss7_location_leak", "cellular_stationary_change", 0.3),
        ("power_drain", "cellular_rat_downgrade", 0.15),
        ("sensor_ultrasonic", "tamper_case_open", 0.25),
    ]

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        logger.info("Scorer started (mode=%s)", SCORER_MODE)

    @classmethod
    def stop(cls):
        pass

    @classmethod
    def ingest(cls, source: str, heuristic: str, confidence: float, detail: str = ""):
        with cls._lock:
            cls._events.append({
                "time": time.time(),
                "source": source,
                "heuristic": heuristic,
                "confidence": min(1.0, max(0.0, confidence)),
                "detail": detail,
            })
            # Keep last 500
            if len(cls._events) > 500:
                cls._events = cls._events[-500:]
            cls._recalculate()

    @classmethod
    def _recalculate(cls):
        now = time.time()
        window_start = now - SCORER_TEMPORAL_WINDOW
        recent = [e for e in cls._events if e["time"] >= window_start]

        if not recent:
            cls._current_score = 0.0
            return

        # Base score: highest weighted confidence
        base_score = 0.0
        for e in recent:
            w = cls.WEIGHTS.get(e["heuristic"], 0.3)
            base_score = max(base_score, e["confidence"] * w)

        # Synergy bonus: correlated pairs within window
        synergy = 0.0
        for i, a in enumerate(recent):
            for b in recent[i + 1:]:
                pair_dt = abs(a["time"] - b["time"])
                if pair_dt > SCORER_TEMPORAL_WINDOW:
                    continue
                for h1, h2, bonus in cls.PAIR_SYNERGY:
                    if {a["heuristic"], b["heuristic"]} == {h1, h2}:
                        synergy += bonus * a["confidence"] * b["confidence"]

        cls._current_score = min(1.0, base_score + synergy)

        cls._score_history.append({
            "time": now,
            "score": cls._current_score,
            "base": base_score,
            "synergy": synergy,
            "event_count": len(recent),
        })
        if len(cls._score_history) > 1000:
            cls._score_history = cls._score_history[-1000:]

    @classmethod
    def get_score(cls) -> float:
        return cls._current_score

    @classmethod
    def get_threat_level(cls) -> int:
        s = cls._current_score
        if s >= 0.8:
            return 4  # CRITICAL
        if s >= 0.6:
            return 3  # HIGH
        if s >= 0.35:
            return 2  # MEDIUM
        if s >= 0.15:
            return 1  # LOW
        return 0  # NONE

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "mode": SCORER_MODE,
            "current_score": cls._current_score,
            "threat_level": cls.get_threat_level(),
            "threat_label": THREAT_LABELS[cls.get_threat_level()],
            "events_in_window": len([e for e in cls._events
                                     if e["time"] >= time.time() - SCORER_TEMPORAL_WINDOW]),
            "total_events": len(cls._events),
        }

    @classmethod
    def explain(cls) -> list[dict]:
        now = time.time()
        recent = [e for e in cls._events if e["time"] >= now - SCORER_TEMPORAL_WINDOW]
        return [
            {
                "time": e["time"],
                "age_s": int(now - e["time"]),
                "source": e["source"],
                "heuristic": e["heuristic"],
                "confidence": e["confidence"],
                "weight": cls.WEIGHTS.get(e["heuristic"], 0.3),
                "detail": e["detail"],
            }
            for e in sorted(recent, key=lambda x: x["confidence"], reverse=True)[:20]
        ]

    @classmethod
    def get_history(cls, limit: int = 100) -> list[dict]:
        return cls._score_history[-limit:]
