from __future__ import annotations

import json
import logging
import os
import random
import subprocess
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

EMSEC_ENABLED = os.environ.get("CPIP_EMSEC", "0") == "1"
EMSEC_FARADAY_INTERVAL = int(os.environ.get("CPIP_EMSEC_FARADAY_TEST_INTERVAL", "3600"))
EMSEC_FARADAY_RX_GAIN = int(os.environ.get("CPIP_EMSEC_FARADAY_RX_GAIN", "10"))
EMSEC_TIMING_JITTER = int(os.environ.get("CPIP_EMSEC_TIMING_JITTER_MS", "50"))


class EMSecProvider(BaseProvider):
    TYPE = ProviderType.SECURITY
    NAME = "emsec"
    VERSION = "6.0.0"

    _running = False
    _faraday_intact = True
    _alerts: list[dict] = []

    @classmethod
    def is_available(cls) -> bool:
        return EMSEC_ENABLED

    @classmethod
    def start(cls):
        if not EMSEC_ENABLED or cls._running:
            return
        cls._running = True
        threading.Thread(target=cls._faraday_check_loop, daemon=True).start()
        logger.info("EMSecProvider started")

    @classmethod
    def _faraday_check_loop(cls):
        while cls._running:
            time.sleep(EMSEC_FARADAY_INTERVAL)
            try:
                cls._test_faraday()
            except Exception as e:
                logger.debug("Faraday test error: %s", e)

    @classmethod
    def _test_faraday(cls):
        try:
            result = subprocess.run(
                ["rpitx", "-m", "RF", "-f", "433.92e6", "-i", "/dev/urandom", "-l", "1"],
                capture_output=True, text=True, timeout=3, check=False)
            rx_result = subprocess.run(
                ["rtl_power", "-f", "433.92e6:433.93e6:1e3", "-i", "1", "-1"],
                capture_output=True, text=True, timeout=5, check=False)
            if rx_result.returncode == 0 and rx_result.stdout.strip():
                lines = rx_result.stdout.strip().split("\n")
                powers = []
                for line in lines[-5:]:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        try:
                            powers.append(float(parts[2]))
                        except ValueError:
                            pass
                if powers:
                    avg_reflected = sum(powers) / len(powers)
                    cls._faraday_intact = avg_reflected < -80
                    if not cls._faraday_intact:
                        cls._alerts.append({
                            "time": time.time(),
                            "event": "faraday_compromised",
                            "reflected_power_dbm": avg_reflected,
                        })
        except Exception:
            pass

    @classmethod
    def scan_emissions(cls) -> list[dict]:
        emissions = []
        try:
            result = subprocess.run(
                ["rtl_power", "-f", "100e6:6e9:1e6", "-i", "1", "-1"],
                capture_output=True, text=True, timeout=30, check=False)
            if result.stdout:
                for line in result.stdout.strip().split("\n")[:20]:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        try:
                            freq = float(parts[0])
                            power = float(parts[2])
                            if power > -50:
                                emissions.append({"freq_mhz": freq / 1e6, "power_dbm": power})
                        except ValueError:
                            pass
        except Exception:
            pass
        return emissions

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": EMSEC_ENABLED,
            "running": cls._running,
            "faraday_intact": cls._faraday_intact,
            "timing_jitter_ms": EMSEC_TIMING_JITTER,
            "alerts": cls._alerts[-5:] if cls._alerts else [],
        }
