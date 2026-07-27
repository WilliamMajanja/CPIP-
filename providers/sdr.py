from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

SDR_ENABLED = os.environ.get("CPIP_SDR", "0") == "1"
SDR_DEVICE = os.environ.get("CPIP_SDR_DEVICE", "rtlsdr")
SDR_GAIN = os.environ.get("CPIP_SDR_GAIN", "auto")
SDR_BANDS = os.environ.get("CPIP_SDR_BANDS", "B2,B4,B5,B12,B13,B66,n71,n78")
SDR_IQ_DIR = os.environ.get("CPIP_SDR_IQ_DIR", "/tmp/cpip_evidence")
SDR_CAPTURE_DURATION = int(os.environ.get("CPIP_SDR_CAPTURE_DURATION", "10"))

LTE_BAND_CENTER_FREQ = {
    "B2": 1930e6, "B4": 2130e6, "B5": 881e6, "B12": 737e6,
    "B13": 751e6, "B66": 2155e6, "n71": 637e6, "n78": 3500e6,
}


class SDRBackend(Enum):
    RTLSDR = "rtlsdr"
    HACKRF = "hackrf"
    SOAPY = "soapy"


class SDRProvider(BaseProvider):
    TYPE = ProviderType.SDR
    NAME = "sdr"
    VERSION = "6.0.3"

    _instance: ClassVar[SDRProvider | None] = None
    _running = False
    _thread: threading.Thread | None = None
    _scan_results: dict[str, Any] = {}
    _spectrum_subscribers: list = []
    _alerts: list[dict[str, Any]] = []
    _rf_fingerprints: dict[str, dict[str, float]] = {}

    @classmethod
    def is_available(cls) -> bool:
        try:
            result = subprocess.run(
                ["rtl_test", "-t"], capture_output=True, text=True, timeout=3, check=False)
            return result.returncode == 0
        except FileNotFoundError:
            try:
                result = subprocess.run(
                    ["SoapySDRUtil", "--info"], capture_output=True, text=True, timeout=3, check=False)
                return result.returncode == 0
            except FileNotFoundError:
                return False

    @classmethod
    def start(cls):
        if not SDR_ENABLED or cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._sdr_loop, daemon=True)
        cls._thread.start()
        logger.info("SDRProvider started")

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _sdr_loop(cls):
        while cls._running:
            try:
                cls._passive_scan()
            except Exception as e:
                logger.debug("SDR scan error: %s", e)
            time.sleep(60)

    @classmethod
    def _passive_scan(cls):
        results = {}
        for band in SDR_BANDS.split(","):
            band = band.strip()
            freq = LTE_BAND_CENTER_FREQ.get(band)
            if not freq:
                continue
            try:
                cells = cls._scan_band_rtl(band, freq)
                if cells:
                    results[band] = cells
            except Exception:
                pass
        cls._scan_results = {
            "timestamp": time.time(),
            "bands": results,
            "cell_count": sum(len(c) for c in results.values()),
        }

    @classmethod
    def _scan_band_rtl(cls, band: str, freq: float) -> list[dict]:
        gain_arg = f"-g {SDR_GAIN}" if SDR_GAIN != "auto" else ""
        cmd = f"rtl_power -f {freq-5e6}:{freq+5e6}:1e6 -i 5 -1 2>/dev/null"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        cells = []
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n")[-10:]:
                parts = line.split(",")
                if len(parts) >= 4:
                    try:
                        freq_hz = float(parts[0])
                        power = float(parts[2])
                        cells.append({"freq_mhz": freq_hz / 1e6, "power_dbm": power, "band": band})
                    except ValueError:
                        pass

        try:
            detect_cmd = f"cell_search -b {band} -f {freq/1e6} -a 2>/dev/null"
            det_result = subprocess.run(detect_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if "Found CELL" in det_result.stdout:
                for line in det_result.stdout.splitlines():
                    if "Found CELL" in line:
                        cells.append({"raw": line.strip(), "band": band, "detected": True})
        except Exception:
            pass

        return cells

    @classmethod
    def capture_iq(cls, duration: int = SDR_CAPTURE_DURATION) -> dict:
        Path(SDR_IQ_DIR).mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        outpath = Path(SDR_IQ_DIR) / f"iq_capture_{ts}.cu8"
        try:
            result = subprocess.run(
                ["rtl_sdr", str(outpath), "-s", "2.4e6", "-n", f"{duration * 2_400_000}"],
                capture_output=True, text=True, timeout=duration + 10)
            return {"path": str(outpath), "size": outpath.stat().st_size if outpath.exists() else 0,
                    "duration": duration, "status": "ok" if result.returncode == 0 else "error"}
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def get_spectrum(cls) -> dict[str, Any]:
        return {
            "running": cls._running,
            "device": SDR_DEVICE,
            "gain": SDR_GAIN,
            "scan": cls._scan_results,
        }

    @classmethod
    def scan_band(cls, band: str) -> list[dict]:
        freq = LTE_BAND_CENTER_FREQ.get(band)
        if not freq:
            return []
        return cls._scan_band_rtl(band, freq)

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": SDR_ENABLED,
            "running": cls._running,
            "device": SDR_DEVICE,
            "available": cls.is_available(),
            "bands": SDR_BANDS,
            "last_scan": cls._scan_results,
        }


class SpectrumDefense:
    """Frequency hopping, burst TX, jammer detection (RFC-0004)."""

    _running = False
    _thread: threading.Thread | None = None
    _current_channel = 0
    _noise_floor: list[float] = []
    _jammer_detected = False
    _jammer_cooldown = 0

    HOP_SEQ = [int(f) for f in os.environ.get("CPIP_RADIO_HOP_SEQ", "915000000,916000000,917000000").split(",") if f.strip().isdigit()]
    HOP_INTERVAL = int(os.environ.get("CPIP_RADIO_HOP_INTERVAL", "30"))
    BURST_ENABLED = os.environ.get("CPIP_RADIO_BURST", "1") == "1"
    BURST_DURATION = int(os.environ.get("CPIP_RADIO_BURST_DURATION", "50"))
    JAMMER_THRESHOLD = int(os.environ.get("CPIP_RADIO_JAMMER_THRESHOLD", "-40"))
    JAMMER_COOLDOWN = int(os.environ.get("CPIP_RADIO_JAMMER_COOLDOWN", "60"))

    @classmethod
    def start(cls):
        if cls._running or len(cls.HOP_SEQ) < 2:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._hop_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _hop_loop(cls):
        while cls._running:
            try:
                cls._check_jammer()
                if cls._jammer_detected and time.time() > cls._jammer_cooldown:
                    cls._jammer_detected = False
                idx = (cls._current_channel + 1) % len(cls.HOP_SEQ)
                cls._current_channel = idx
            except Exception as e:
                logger.debug("Hop error: %s", e)
            time.sleep(cls.HOP_INTERVAL)

    @classmethod
    def _check_jammer(cls):
        try:
            result = subprocess.run(
                ["rtl_power", "-f", f"{cls.HOP_SEQ[0]-1e6}:{cls.HOP_SEQ[0]+1e6}:1e6", "-i", "1", "-1"],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n")[-3:]:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        try:
                            power = float(parts[2])
                            cls._noise_floor.append(power)
                            if len(cls._noise_floor) > 10:
                                cls._noise_floor.pop(0)
                            avg_noise = sum(cls._noise_floor) / len(cls._noise_floor)
                            if avg_noise > cls.JAMMER_THRESHOLD and not cls._jammer_detected:
                                cls._jammer_detected = True
                                cls._jammer_cooldown = time.time() + cls.JAMMER_COOLDOWN
                                logger.warning("JAMMER DETECTED: noise floor %.1f dBm", avg_noise)
                        except ValueError:
                            pass
        except Exception:
            pass

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "running": cls._running,
            "hop_sequence": cls.HOP_SEQ,
            "hop_interval": cls.HOP_INTERVAL,
            "current_channel": cls._current_channel,
            "current_freq": cls.HOP_SEQ[cls._current_channel] if cls.HOP_SEQ else None,
            "jammer_detected": cls._jammer_detected,
            "burst_enabled": cls.BURST_ENABLED,
            "noise_floor": sum(cls._noise_floor) / len(cls._noise_floor) if cls._noise_floor else None,
        }
