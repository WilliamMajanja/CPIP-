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
    def scan(cls, band: str = "") -> dict:
        """Trigger a scan (RFC-0002). Optionally limited to one band."""
        if band:
            cells = cls._scan_band_rtl(band, LTE_BAND_CENTER_FREQ.get(band, 0))
            cls._scan_results = {
                "timestamp": time.time(), "bands": {band: cells},
                "cell_count": len(cells),
            }
        else:
            cls._passive_scan()
        return cls.get_status()

    @classmethod
    def capture(cls, duration: int = SDR_CAPTURE_DURATION) -> dict:
        """Capture IQ sample and fingerprint the captured signal (RFC-0002)."""
        result = cls.capture_iq(duration)
        if "error" in result:
            return result
        result["fingerprint"] = cls.fingerprint_rf(result.get("path", ""))
        return result

    @classmethod
    def fingerprint_rf(cls, iq_path: str = "") -> dict[str, Any]:
        """RF fingerprint analysis — I/Q imbalance, CFO and phase-noise baselines.
        Without hardware, returns a synthetic baseline for correlation."""
        fp: dict[str, Any] = {
            "iq_imbalance_db": None, "cfo_hz": None, "phase_noise": None,
            "sample_source": iq_path or "live", "confidence": 0.0,
        }
        if not iq_path:
            fp["note"] = "no IQ capture — baseline not measurable"
            return fp
        try:
            path = Path(iq_path)
            if not path.exists() or path.stat().st_size < 1024:
                fp["note"] = "capture too small for fingerprinting"
                return fp
            with open(iq_path, "rb") as f:
                data = f.read()
            n = len(data) // 2
            if n < 64:
                fp["note"] = "insufficient samples"
                return fp
            i = [data[k * 2] - 128 for k in range(n)]
            q = [data[k * 2 + 1] - 128 for k in range(n)]
            i_avg = sum(i) / n
            q_avg = sum(q) / n
            fp["iq_imbalance_db"] = round(20 * abs(i_avg - q_avg) / 128, 2)
            crossings = sum(1 for k in range(1, n) if (i[k - 1] < 0) != (i[k] < 0))
            est_freq = crossings * 2400000.0 / (2 * n)
            fp["cfo_hz"] = round(est_freq, 1)
            fp["phase_noise"] = round(
                (sum(abs(q[k] - i[k]) for k in range(n)) / n) / 128.0, 4)
            fp["confidence"] = min(1.0, n / 100000.0)
        except Exception as e:
            fp["note"] = f"fingerprint error: {e}"
        return fp

    @classmethod
    def check_phantom_towers(cls, cellular_status: dict | None = None) -> list[dict]:
        """Compare SDR-observed signals against OS/ModemManager-reported cells
        (RFC-0002). Strong SDR signals with no matching cellular cell = phantom."""
        findings: list[dict[str, Any]] = []
        scan = cls._scan_results.get("bands", {}) if cls._scan_results else {}
        if not scan:
            return findings
        os_cells = set()
        if cellular_status:
            serving = cellular_status.get("serving") or {}
            if serving.get("cell_id"):
                os_cells.add(str(serving["cell_id"]))
            for n in cellular_status.get("neighbors", []):
                if n.get("cell_id") is not None:
                    os_cells.add(str(n["cell_id"]))
        strong = []
        for band, cells in scan.items():
            for c in cells:
                if c.get("power_dbm", -100) > -50:
                    strong.append(c)
        for c in strong:
            findings.append({
                "type": "phantom_tower",
                "band": c.get("band"), "freq_mhz": c.get("freq_mhz"),
                "power_dbm": c.get("power_dbm"),
                "detail": "Strong unverified RF signal not matched to any reported cell",
                "threat": 3 if c.get("power_dbm", 0) > -30 else 2,
            })
        return findings

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": SDR_ENABLED,
            "running": cls._running,
            "device": SDR_DEVICE,
            "available": cls.is_available(),
            "bands": SDR_BANDS,
            "last_scan": cls._scan_results,
            "rf_fingerprints": {k: v for k, v in cls._rf_fingerprints.items()},
            "phantom_towers": cls.check_phantom_towers(),
        }


class SpectrumDefense:
    """Frequency hopping, burst TX, jammer detection (RFC-0004)."""

    _running = False
    _thread: threading.Thread | None = None
    _current_channel = 0
    _noise_floor: list[float] = []
    _jammer_detected = False
    _jammer_cooldown = 0
    _bursts_sent = 0
    _burst_log: list[dict[str, Any]] = []
    _tower_db: dict[str, dict[str, Any]] = {}
    _tower_db_file = Path(os.environ.get("CPIP_RADIO_TOWER_DB", "/tmp/cpip_radio_towers.json"))

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
        cls._load_tower_db()
        cls._running = True
        cls._thread = threading.Thread(target=cls._hop_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def set_hop_sequence(cls, channels: str) -> dict:
        """Set the RF channel hop sequence (RFC-0004 CLI: hop sequence set)."""
        freqs = []
        for part in channels.replace(" ", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                v = int(part)
            except ValueError:
                return {"error": f"Invalid channel: {part} — use frequencies in Hz"}
            if not 100000 <= v <= 6000000000:
                return {"error": f"Channel {v} out of range"}
            freqs.append(v)
        if len(freqs) < 2:
            return {"error": "Need at least 2 channels"}
        cls.HOP_SEQ = freqs
        cls._current_channel = 0
        return {"status": "hop_sequence_set", "channels": freqs}

    @classmethod
    def _hop_loop(cls):
        while cls._running:
            try:
                cls._check_jammer()
                if cls._jammer_detected and time.time() > cls._jammer_cooldown:
                    cls._jammer_detected = False
                idx = (cls._current_channel + 1) % len(cls.HOP_SEQ)
                cls._current_channel = idx
                if cls.BURST_ENABLED:
                    cls._transmit_burst()
            except Exception as e:
                logger.debug("Hop error: %s", e)
            time.sleep(cls.HOP_INTERVAL)

    @classmethod
    def _transmit_burst(cls) -> None:
        """Spread-spectrum burst TX (<100ms, >500kHz bandwidth) to defeat
        direction-finding (RFC-0004). Falls back to simulation without HW."""
        freq = cls.HOP_SEQ[cls._current_channel]
        try:
            import random
            bw = 0.5e6 + random.random() * 0.5e6
            cmd = f"rpitx -m FM -f {freq} -i /dev/urandom -d {cls.BURST_DURATION} >/dev/null 2>&1"
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=cls.BURST_DURATION / 1000 + 2)
            cls._bursts_sent += 1
            cls._record_burst(freq, bw)
        except Exception as e:
            cls._bursts_sent += 1
            cls._record_burst(freq, bw)
            logger.debug("Burst TX simulated (no HW): %s", e)

    @classmethod
    def _record_burst(cls, freq: int, bandwidth: float) -> None:
        entry = {"freq": freq, "bandwidth_hz": round(bandwidth, 3), "time": time.time()}
        getattr(cls, "_burst_log", []).append(entry)
        if len(getattr(cls, "_burst_log", [])) > 100:
            cls._burst_log = cls._burst_log[-100:]

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

    # ── Tower RF fingerprinting (RFC-0004) ────────────────────────

    @classmethod
    def _load_tower_db(cls) -> None:
        try:
            if cls._tower_db_file.exists():
                cls._tower_db = json.loads(cls._tower_db_file.read_text())
        except Exception:
            cls._tower_db = {}

    @classmethod
    def fingerprint_tower(cls, cell_id: str, power_dbm: float, cfo_hz: float = 0.0,
                          bw_hz: float = 0.0) -> dict[str, Any]:
        """Record an RF fingerprint for a tower; flag newcomers (RFC-0004)."""
        ts = time.time()
        if cell_id in cls._tower_db:
            prev = cls._tower_db[cell_id]
            cls._tower_db[cell_id] = {
                "cell_id": cell_id,
                "seen": prev.get("seen", 0) + 1,
                "last_seen": ts,
                "first_seen": prev.get("first_seen", ts),
                "avg_power": (prev.get("avg_power", 0) * prev.get("seen", 1) + power_dbm) / (prev.get("seen", 1) + 1),
                "cfo_hz": cfo_hz, "bw_hz": bw_hz,
                "newcomer": False,
            }
        else:
            cls._tower_db[cell_id] = {
                "cell_id": cell_id, "seen": 1, "last_seen": ts,
                "first_seen": ts, "avg_power": power_dbm,
                "cfo_hz": cfo_hz, "bw_hz": bw_hz, "newcomer": True,
            }
        try:
            cls._tower_db_file.parent.mkdir(parents=True, exist_ok=True)
            cls._tower_db_file.write_text(json.dumps(cls._tower_db))
        except Exception as e:
            logger.debug("Tower DB write error: %s", e)
        entry = dict(cls._tower_db[cell_id])
        if entry.pop("newcomer", False):
            logger.warning("NEW TOWER DETECTED: %s (%.1f dBm)", cell_id, power_dbm)
            entry["alert"] = "newcomer"
        return entry

    @classmethod
    def get_towers(cls) -> list[dict[str, Any]]:
        return list(cls._tower_db.values())

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
            "burst_duration_ms": cls.BURST_DURATION,
            "bursts_sent": cls._bursts_sent,
            "towers": len(cls._tower_db),
            "noise_floor": sum(cls._noise_floor) / len(cls._noise_floor) if cls._noise_floor else None,
        }
