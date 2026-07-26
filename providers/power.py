from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

POWER_MONITOR = os.environ.get("CPIP_POWER_MONITOR", "1") == "1"
POWER_I2C_ADDR = int(os.environ.get("CPIP_POWER_I2C_ADDR", "0x40"), 16)
POWER_DRAIN_THRESHOLD = float(os.environ.get("CPIP_POWER_DRAIN_THRESHOLD", "2.0"))


class PowerProvider(BaseProvider):
    TYPE = ProviderType.POWER
    NAME = "power"
    VERSION = "6.0.0"

    _running = False
    _thread: threading.Thread | None = None
    _baseline: dict[str, float] = {}
    _current_draw: list[float] = []
    _alerts: list[dict] = []
    _sample_count = 0

    @classmethod
    def is_available(cls) -> bool:
        try:
            import smbus2
            bus = smbus2.SMBus(1)
            bus.read_word_data(POWER_I2C_ADDR, 0x00)
            bus.close()
            return True
        except Exception:
            return os.path.exists("/sys/class/power_supply")

    @classmethod
    def start(cls):
        if not POWER_MONITOR or cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._monitor_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def _monitor_loop(cls):
        while cls._running:
            try:
                current = cls._read_current()
                if current:
                    cls._current_draw.append(current)
                    if len(cls._current_draw) > 3600:
                        cls._current_draw.pop(0)
                    cls._analyze(current)
            except Exception:
                pass
            time.sleep(2)

    @classmethod
    def _read_current(cls) -> float | None:
        try:
            import smbus2
            bus = smbus2.SMBus(1)
            raw = bus.read_word_data(POWER_I2C_ADDR, 0x04)
            bus.close()
            current_ma = raw * 0.1  # INA219
            return current_ma
        except Exception:
            pass
        try:
            for path in ["/sys/class/power_supply/BAT0/current_now"]:
                if os.path.exists(path):
                    with open(path) as f:
                        val = int(f.read().strip())
                        return val / 1000.0  # µA to mA
        except Exception:
            pass
        return None

    @classmethod
    def _analyze(cls, current: float):
        cls._sample_count += 1
        if cls._sample_count < 10:
            return
        avg = sum(cls._current_draw[-30:]) / min(len(cls._current_draw[-30:]), 30)
        if cls._current_draw and avg > 0:
            baseline = sum(cls._current_draw[-300:]) / max(len(cls._current_draw[-300:]), 1)
            if baseline > 0 and avg > baseline * POWER_DRAIN_THRESHOLD:
                cls._alerts.append({
                    "time": time.time(),
                    "current_ma": current,
                    "avg_30s": avg,
                    "baseline": baseline,
                    "ratio": avg / baseline if baseline else 0,
                })
                if len(cls._alerts) > 50:
                    cls._alerts = cls._alerts[-50:]

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "monitoring": POWER_MONITOR,
            "running": cls._running,
            "current_ma": cls._current_draw[-1] if cls._current_draw else None,
            "avg_1min": sum(cls._current_draw[-30:]) / max(len(cls._current_draw[-30:]), 1) if cls._current_draw else None,
            "samples": cls._sample_count,
            "alerts": cls._alerts[-5:] if cls._alerts else [],
        }

    @classmethod
    def get_log(cls, minutes: int = 5) -> list[dict]:
        samples_needed = minutes * 30
        recent = cls._current_draw[-samples_needed:] if cls._current_draw else []
        return [{"index": i, "ma": v} for i, v in enumerate(recent)]
