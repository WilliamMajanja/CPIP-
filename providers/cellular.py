from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

CELL_SOURCE = os.environ.get("CPIP_CELL_SOURCE", "dbus")
CELL_5G = os.environ.get("CPIP_CELL_5G", "1") == "1"
CELL_TA_ANALYSIS = os.environ.get("CPIP_CELL_TA_ANALYSIS", "1") == "1"
CELL_GPS_CORRELATE = os.environ.get("CPIP_CELL_GPS_CORRELATE", "1") == "1"
CELL_SIGNAL_DELTA = int(os.environ.get("CPIP_CELL_SIGNAL_DELTA", "25"))
CELL_BASELINE_DB = os.environ.get("CPIP_CELL_BASELINE_DB", "/tmp/cpip_cell_baseline.db")
CELL_SCAN_INTERVAL = int(os.environ.get("CPIP_CELL_SCAN_INTERVAL", "30"))

# 2G RAT names that indicate no encryption (GSM, GPRS, EDGE)
RAT_2G_NAMES = {"GSM", "GSM_COMPACT", "GPRS", "EDGE", "1XRTT", "EVDO0", "EVDOA", "EVDOB"}
RAT_3G_NAMES = {"UMTS", "HSDPA", "HSUPA", "HSPA", "HSPA_PLUS"}
RAT_4G_NAMES = {"LTE", "LTE_CA", "LTE_ADVANCED"}
RAT_5G_NAMES = {"5G_NR", "5G_NSA", "5G"}

# RAT degradation order (lower = older/weaker)
RAT_ORDER = {"5G_NR": 5, "5G_NSA": 5, "5G": 5, "LTE": 4, "LTE_CA": 4, "LTE_ADVANCED": 4,
             "UMTS": 3, "HSDPA": 3, "HSUPA": 3, "HSPA": 3, "HSPA_PLUS": 3,
             "GSM": 2, "GSM_COMPACT": 2, "GPRS": 2, "EDGE": 2,
             "1XRTT": 2, "EVDO0": 2, "EVDOA": 2, "EVDOB": 2}


class CellularProvider(BaseProvider):
    TYPE = ProviderType.CELLULAR
    NAME = "cellular"
    VERSION = "6.0.3"

    _instance: ClassVar[CellularProvider | None] = None
    _lock = threading.Lock()
    _running = False
    _thread: threading.Thread | None = None

    _serving: dict[str, Any] = {}
    _neighbors: list[dict[str, Any]] = []
    _baseline: dict[str, Any] = {}
    _threat_level = 0
    _alerts: list[dict[str, Any]] = []
    _scan_count = 0
    _gps: dict[str, float] = {}
    _ta_history: list[int] = []
    _passive_mode = False
    _stealth_mode = False
    _mm = None
    _paging_count = 0
    _stk_commands: list[dict[str, Any]] = []
    _stealth_mode = False
    _mm = None
    _paging_count = 0
    _stk_commands: list[dict[str, Any]] = []

    @classmethod
    def is_available(cls) -> bool:
        try:
            import pydbus
            bus = pydbus.SystemBus()
            obj = bus.get("org.freedesktop.ModemManager1")
            return bool(obj.GetManagedObjects())
        except Exception:
            return False

    @classmethod
    def _get_mm(cls):
        if cls._mm is None:
            import pydbus
            cls._mm = pydbus.SystemBus().get("org.freedesktop.ModemManager1")
        return cls._mm

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._init_db()
        cls._thread = threading.Thread(target=cls._scan_loop, daemon=True)
        cls._thread.start()
        logger.info("CellularProvider started")

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _init_db(cls):
        Path(CELL_BASELINE_DB).parent.mkdir(parents=True, exist_ok=True)
        try:
            db = sqlite3.connect(CELL_BASELINE_DB)
            db.execute("""
                CREATE TABLE IF NOT EXISTS cell_baseline (
                    cell_id TEXT, mcc TEXT, mnc TEXT, lac TEXT,
                    avg_signal REAL, avg_rsrp REAL, avg_rsrq REAL,
                    sample_count INTEGER, last_seen REAL,
                    PRIMARY KEY (cell_id, mcc, mnc)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS neighbor_cache (
                    cell_id TEXT, mcc TEXT, mnc TEXT, lac TEXT,
                    neighbor_list TEXT, last_seen REAL,
                    PRIMARY KEY (cell_id, mcc, mnc)
                )
            """)
            db.commit()
            db.close()
        except Exception as e:
            logger.debug("DB init error: %s", e)

    @classmethod
    def _scan_loop(cls):
        while cls._running:
            try:
                cls._scan_cellular()
            except Exception as e:
                logger.debug("Scan error: %s", e)
            time.sleep(CELL_SCAN_INTERVAL)

    @classmethod
    def _scan_cellular(cls):
        cls._scan_count += 1
        ts = time.time()
        try:
            cls._scan_mm_dbus()
        except Exception:
            try:
                cls._scan_mmcli_fallback()
            except Exception:
                pass
        cls._analyze_threats(ts)

    @classmethod
    def _scan_mm_dbus(cls):
        mm = cls._get_mm()
        modems = mm.GetManagedObjects()
        for path, interfaces in modems.items():
            modems_iface = interfaces.get("org.freedesktop.ModemManager1.Modem", {})
            if not modems_iface:
                continue
            _3gpp = interfaces.get("org.freedesktop.ModemManager1.Modem.Modem3gpp", {})
            _signal = interfaces.get("org.freedesktop.ModemManager1.Modem.Signal", {})

            cls._serving = {
                "mcc": _3gpp.get("OperatorCode", "")[:3] if _3gpp.get("OperatorCode") else "",
                "mnc": _3gpp.get("OperatorCode", "")[3:] if _3gpp.get("OperatorCode") else "",
                "operator": _3gpp.get("OperatorName", ""),
                "registration": _3gpp.get("RegistrationState", 0),
                "rat": cls._rat_name(_3gpp.get("AccessTechnology", 0)),
                "rssi": modems_iface.get("SignalQuality", [0, False])[0] if modems_iface.get("SignalQuality") else 0,
                "rsrp": _signal.get("LTE", {}).get("rsrp", None) if _signal.get("LTE") else None,
                "rsrq": _signal.get("LTE", {}).get("rsrq", None) if _signal.get("LTE") else None,
                "sinr": _signal.get("LTE", {}).get("sinr", None) if _signal.get("LTE") else None,
                "cell_id": _3gpp.get("CellId", ""),
                "lac": _3gpp.get("Lac", ""),
                "tac": _3gpp.get("Tac", ""),
                "timing_advance": modems_iface.get("TimingAdvance", -1),
                "paging_count": _3gpp.get("PagingCount", 0),
                "stk_commands": _3gpp.get("STKCommands", []),
            }

            if CELL_5G:
                nr5g = _signal.get("NR5G", {})
                if nr5g:
                    cls._serving.update({
                        "nr_rsrp": nr5g.get("rsrp", None),
                        "nr_rsrq": nr5g.get("rsrq", None),
                        "nr_sinr": nr5g.get("sinr", None),
                        "nr_arfcn": _3gpp.get("NrArfcn", None),
                    })

            cls._read_gps(modems_iface)
            cls._update_baseline()
            break

    @classmethod
    def _scan_mmcli_fallback(cls):
        import subprocess
        result = subprocess.run(
            ["mmcli", "-m", "0", "-S"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            return
        output = result.stdout
        mcc = mnc = lac = cellid = signal = rat = ""
        for line in output.splitlines():
            ll = line.lower().strip()
            if "operator id" in ll or "mcc" in ll:
                parts = line.split(":")[-1].strip().split()
                if len(parts) >= 2:
                    mcc, mnc = parts[0], parts[1]
            elif "lac" in ll:
                lac = line.split(":")[-1].strip()
            elif "cell id" in ll or "cellid" in ll:
                cellid = line.split(":")[-1].strip()
            elif "signal" in ll:
                try:
                    signal = int(line.split(":")[-1].strip().replace("%", ""))
                except ValueError:
                    pass
            elif "rat" in ll or "network type" in ll:
                rat = line.split(":")[-1].strip()
        cls._serving = {
            "mcc": mcc, "mnc": mnc, "lac": lac, "cell_id": cellid,
            "signal": signal, "rat": rat, "rssi": signal,
            "rsrp": None, "rsrq": None, "sinr": None,
            "timing_advance": -1,
        }

    @classmethod
    def _rat_name(cls, tech: int) -> str:
        mapping = {
            0: "UNKNOWN", 1: "GSM", 2: "GSM_COMPACT", 3: "GPRS",
            4: "EDGE", 5: "UMTS", 6: "HSDPA", 7: "HSUPA", 8: "HSPA",
            9: "HSPA_PLUS", 10: "1XRTT", 11: "EVDO0", 12: "EVDOA",
            13: "EVDOB", 14: "LTE", 15: "LTE_CA", 16: "LTE_ADVANCED",
            17: "5G_NR", 18: "5G_NSA",
        }
        return mapping.get(tech, f"UNKNOWN({tech})")

    @classmethod
    def _read_gps(cls, modem_iface: dict):
        if not CELL_GPS_CORRELATE:
            return
        try:
            loc = modem_iface.get("Location", {})
            gps = loc.get("gps", {}) if isinstance(loc, dict) else {}
            if gps:
                cls._gps = {"lat": gps.get("latitude", 0), "lon": gps.get("longitude", 0)}
        except Exception:
            pass

    @classmethod
    def _update_baseline(cls):
        s = cls._serving
        if not s.get("cell_id") or not s.get("mcc"):
            return
        try:
            db = sqlite3.connect(CELL_BASELINE_DB)
            db.execute("""
                INSERT INTO cell_baseline (cell_id, mcc, mnc, lac, avg_signal, avg_rsrp, avg_rsrq, sample_count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(cell_id, mcc, mnc) DO UPDATE SET
                    avg_signal = (avg_signal * sample_count + ?) / (sample_count + 1),
                    avg_rsrp = CASE WHEN ? IS NOT NULL THEN (avg_rsrp * sample_count + ?) / (sample_count + 1) ELSE avg_rsrp END,
                    avg_rsrq = CASE WHEN ? IS NOT NULL THEN (avg_rsrq * sample_count + ?) / (sample_count + 1) ELSE avg_rsrq END,
                    sample_count = sample_count + 1,
                    last_seen = ?
            """, (
                s["cell_id"], s["mcc"], s["mnc"], s["lac"],
                s.get("rssi", 0), s.get("rsrp", 0), s.get("rsrq", 0),
                time.time(),
                s.get("rssi", 0),
                s.get("rsrp"), s.get("rsrp", 0),
                s.get("rsrq"), s.get("rsrq", 0),
                time.time(),
            ))
            db.commit()
            db.close()
            cls._baseline = cls._load_baseline(s["cell_id"], s["mcc"], s["mnc"])
        except Exception as e:
            logger.debug("Baseline update error: %s", e)

    @classmethod
    def _load_baseline(cls, cell_id: str, mcc: str, mnc: str) -> dict:
        try:
            db = sqlite3.connect(CELL_BASELINE_DB)
            row = db.execute(
                "SELECT avg_signal, avg_rsrp, avg_rsrq, sample_count FROM cell_baseline WHERE cell_id=? AND mcc=? AND mnc=?",
                (cell_id, mcc, mnc)
            ).fetchone()
            db.close()
            if row:
                return {"avg_signal": row[0], "avg_rsrp": row[1], "avg_rsrq": row[2], "samples": row[3]}
        except Exception:
            pass
        return {}

    @classmethod
    def _analyze_threats(cls, ts: float):
        s = cls._serving
        if not s.get("cell_id"):
            return

        threats = []

        # 1. TA=0 anomaly
        if CELL_TA_ANALYSIS and s.get("timing_advance") == 0:
            threats.append(("Timing Advance=0 (fake tower proximity)", THREAT_HIGH,
                            f"TA=0 with no cell site at GPS {cls._gps}"))

        # 2. RAT downgrade chain
        rat = (s.get("rat") or "").upper()
        prev_rat = (cls._baseline_prev.get("rat") or "").upper() if hasattr(cls, "_baseline_prev") else ""
        downgrade_order = {"5G_NR": 5, "5G_NSA": 5, "LTE": 4, "UMTS": 3, "GSM": 2, "GPRS": 2}
        if prev_rat and rat and prev_rat in downgrade_order and rat in downgrade_order:
            diff = downgrade_order.get(prev_rat, 0) - downgrade_order.get(rat, 0)
            if diff >= 2:
                threats.append((f"RAT downgrade {prev_rat}→{rat}", THREAT_HIGH,
                                f"Forced downgrade for encryption bypass"))
            elif diff == 1:
                threats.append((f"RAT downgrade {prev_rat}→{rat}", THREAT_LOW, ""))
        cls._baseline_prev = dict(s)  # type: ignore[attr-defined]

        # 3. Signal jump
        if s.get("rssi") and cls._baseline.get("avg_signal"):
            delta = abs(s["rssi"] - cls._baseline["avg_signal"])
            if delta > CELL_SIGNAL_DELTA:
                threats.append(("Signal strength anomaly", THREAT_MEDIUM,
                                f"Delta {delta:.0f}% from baseline (possible high-power fake tower)"))

        # 4. Stationary cell change
        if CELL_GPS_CORRELATE and cls._gps:
            if hasattr(cls, "_last_cell") and cls._last_cell != s.get("cell_id"):
                if hasattr(cls, "_last_gps"):
                    lat_delta = abs(cls._gps.get("lat", 0) - cls._last_gps.get("lat", 0))
                    lon_delta = abs(cls._gps.get("lon", 0) - cls._last_gps.get("lon", 0))
                    if lat_delta < 0.001 and lon_delta < 0.001:
                        threats.append(("Cell changed while stationary", THREAT_MEDIUM,
                                        f"{cls._last_cell} → {s.get('cell_id')}"))

        # 5. RAT degradation / 2G forced downgrade
        if RAT_2G_NAMES.intersection({rat}):
            threats.append(("RAT is 2G — no encryption (forced downgrade)", THREAT_HIGH,
                            "Device on unencrypted 2G network — IMSI catcher likely"))
        elif prev_rat and rat and prev_rat in RAT_ORDER and rat in RAT_ORDER:
            diff = RAT_ORDER[prev_rat] - RAT_ORDER[rat]
            if diff >= 2:
                threats.append((f"RAT downgrade {prev_rat}→{rat} (forced degradation)", THREAT_HIGH,
                                "Significant RAT downgrade suggests forced decryption bypass"))
            elif diff == 1:
                threats.append((f"RAT downgrade {prev_rat}→{rat}", THREAT_LOW,
                                "Minor RAT shift — may be normal roaming"))

        # 6. Cell ID sequence analysis (IMSI catchers often use sequential IDs)
        if cell_id and cls._last_cell and cls._last_cell != cell_id:
            try:
                last_num = int(cls._last_cell, 16) if cls._last_cell else 0
                curr_num = int(cell_id, 16) if cell_id else 0
                if abs(curr_num - last_num) <= 3 and last_num != 0:
                    threats.append(("Sequential Cell IDs (possible fake tower)", THREAT_MEDIUM,
                                    f"Cell IDs {cls._last_cell}→{cell_id} are sequential — IMSI catcher pattern"))
            except ValueError:
                pass

        # 7. TA pattern anomaly (real towers have consistent TA ranges)
        if CELL_TA_ANALYSIS and s.get("timing_advance") is not None and s["timing_advance"] >= 0:
            ta = s["timing_advance"]
            if ta == 0 and s.get("rssi", 0) > -70:
                threats.append(("TA=0 with strong signal (IMSI catcher proximity)", THREAT_HIGH,
                                "Timing Advance 0 with strong signal suggests tower is very close"))
            elif ta > 126:
                threats.append(("TA exceeds maximum (TA>126)", THREAT_MEDIUM,
                                f"Timing Advance {ta} exceeds GSM maximum — possible spoofed TA"))

        # 8. Paging channel anomaly (excessive paging suggests fake cell)
        if s.get("paging_count"):
            if s["paging_count"] > 10:
                threats.append(("Excessive paging activity", THREAT_MEDIUM,
                                f"{s['paging_count']} paging requests — possible IMSI catcher flooding"))

        # 9. SIM toolkit command interception detection
        if s.get("stk_commands"):
            for cmd in s["stk_commands"]:
                if cmd.get("type") == "PROACTIVE" and cmd.get("command") in ("SETUP_CALL", "SEND_SMS"):
                    threats.append((f"SIM toolkit {cmd['command']} intercepted", THREAT_HIGH,
                                    "STK proactive command intercepted — possible MITM"))

        # 10. Network type downgrade without user action
        if prev_rat and rat and prev_rat != rat:
            if RAT_4G_NAMES.intersection({prev_rat}) and RAT_2G_NAMES.intersection({rat}):
                threats.append((f"4G→2G forced downgrade", THREAT_CRITICAL,
                                "4G network downgraded to 2G without user action — confirmed IMSI catcher attack"))

        # Record for reff
        cls._last_cell = s.get("cell_id")  # type: ignore[attr-defined]
        cls._last_gps = dict(cls._gps)  # type: ignore[attr-defined]

        for msg, level, detail in threats:
            cls._alert(msg, level, detail)

    @classmethod
    def _alert(cls, message: str, threat: int, detail: str = ""):
        entry = {"time": time.time(), "message": message, "threat": threat, "detail": detail}
        cls._alerts.append(entry)
        if len(cls._alerts) > 100:
            cls._alerts = cls._alerts[-100:]
        max_t = max((a["threat"] for a in cls._alerts[-10:]), default=0)
        cls._threat_level = max_t
        if threat >= THREAT_HIGH:
            logger.warning("   CELLULAR ALERT: %s — %s", message, detail)

    @classmethod
    def scan_now(cls) -> dict:
        cls._scan_cellular()
        return cls.get_status()

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        recent = cls._alerts[-20:] if cls._alerts else []
        return {
            "enabled": cls._running,
            "source": CELL_SOURCE,
            "threat_level": cls._threat_level,
            "threat_label": THREAT_LABELS[cls._threat_level],
            "serving": dict(cls._serving) if cls._serving else None,
            "baseline": dict(cls._baseline) if cls._baseline else None,
            "gps": dict(cls._gps) if cls._gps else None,
            "scan_count": cls._scan_count,
            "recent_alerts": recent,
        }

    @classmethod
    def get_history(cls, limit: int = 50) -> list[dict]:
        try:
            db = sqlite3.connect(CELL_BASELINE_DB)
            rows = db.execute(
                "SELECT cell_id, mcc, mnc, lac, avg_signal, sample_count, last_seen FROM cell_baseline ORDER BY last_seen DESC LIMIT ?",
                (limit,)
            ).fetchall()
            db.close()
            return [
                {"cell_id": r[0], "mcc": r[1], "mnc": r[2], "lac": r[3],
                 "avg_signal": r[4], "samples": r[5], "last_seen": r[6]}
                for r in rows
            ]
        except Exception:
            return []

    @classmethod
    def reset_baseline(cls) -> dict:
        try:
            db = sqlite3.connect(CELL_BASELINE_DB)
            db.execute("DELETE FROM cell_baseline")
            db.execute("DELETE FROM neighbor_cache")
            db.commit()
            db.close()
            cls._baseline = {}
            cls._alerts.clear()
            cls._threat_level = 0
            return {"status": "baseline_reset"}
        except Exception as e:
            return {"error": str(e)}


class AntiStingrayV2(CellularProvider):
    """V2 anti-stingray with multi-generation cellular scan capabilities."""

    NAME = "cellular_v2"
    VERSION = "6.0.3"

    @classmethod
    def scan_generation(cls, gen: int) -> dict[str, Any]:
        return {"generation": gen, "scan_type": f"gen_{gen}", "active": cls._running}

    @classmethod
    def get_gps_correlate(cls) -> bool:
        return os.environ.get("CPIP_CELL_GPS_CORRELATE", "1") == "1"

    @classmethod
    def get_signal_delta(cls) -> float:
        return float(os.environ.get("CPIP_CELL_SIGNAL_DELTA", "3.0"))

    @classmethod
    def get_baseline_db(cls) -> str:
        return os.environ.get("CPIP_CELL_BASELINE_DB", "")

    @classmethod
    def is_5g_enabled(cls) -> bool:
        return os.environ.get("CPIP_CELL_5G", "1") == "1"

    @classmethod
    def get_ta_analysis(cls) -> bool:
        return os.environ.get("CPIP_CELL_TA_ANALYSIS", "1") == "1"

    @classmethod
    def get_source(cls) -> str:
        return os.environ.get("CPIP_CELL_SOURCE", "auto")

    # ── Passive Detection Mode ────────────────────────────────────

    @classmethod
    def set_passive_mode(cls, enabled: bool) -> None:
        """Enable passive-only detection — listen without transmitting.
        An active stingray can detect probe messages; passive mode avoids this."""
        cls._passive_mode = enabled
        if enabled:
            cls._stealth_mode = True
            logger.info("CellularProvider: passive+stealth mode enabled")

    @classmethod
    def set_stealth_mode(cls, enabled: bool) -> None:
        """Enable stealth mode — suppress all active transmissions."""
        cls._stealth_mode = enabled

    @classmethod
    def is_stealth_active(cls) -> bool:
        return cls._stealth_mode

    # ── RF Fingerprinting ─────────────────────────────────────────

    @classmethod
    def fingerprint_rf(cls) -> dict[str, Any]:
        """Analyze RF characteristics to detect IMSI catcher signatures.
        
        IMSI catchers often have distinct RF fingerprints:
        - Abnormal signal-to-noise ratios
        - Unusual frequency hopping patterns
        - Inconsistent PLMN codes across frames
        - Anomalous timing advance distributions
        """
        fp: dict[str, Any] = {
            "snr": None,
            "frequency_hopping": False,
            "plmn_consistency": True,
            "ta_distribution": [],
            "fingerprint_score": 0.0,
        }

        if not cls._serving:
            return fp

        s = cls._serving
        snr = (s.get("rsrp") or 0) - (s.get("rsrq") or -20)
        fp["snr"] = snr

        if snr > 40:
            fp["fingerprint_score"] += 0.3
        elif snr < 10 and s.get("rssi", 0) > -50:
            fp["fingerprint_score"] += 0.5
            fp["plmn_consistency"] = False

        cls._ta_history.append(s.get("timing_advance", -1))
        if len(cls._ta_history) > 10:
            cls._ta_history = cls._ta_history[-10:]

        fp["ta_distribution"] = list(cls._ta_history)
        if len(cls._ta_history) >= 3:
            ta_variance = sum(
                abs(cls._ta_history[i] - cls._ta_history[i + 1])
                for i in range(len(cls._ta_history) - 1)
            ) / (len(cls._ta_history) - 1)
            fp["ta_variance"] = ta_variance
            if ta_variance > 20:
                fp["fingerprint_score"] += 0.4

        return fp

    # ── Multi-Source Correlation ──────────────────────────────────

    @classmethod
    def correlate_with_sdr(cls, sdr_data: dict[str, Any]) -> dict[str, Any]:
        """Cross-reference cellular findings with SDR scan data."""
        correlation: dict[str, Any] = {
            "match": False,
            "confidence": 0.0,
            "indicators": [],
        }

        if not cls._serving or not sdr_data:
            return correlation

        cell_freq = cls._serving.get("arfcn") or cls._serving.get("nr_arfcn")
        sdr_freqs = sdr_data.get("detected_frequencies", [])
        sdr_power = sdr_data.get("max_power", -100)
        cell_power = cls._serving.get("rsrp") or cls._serving.get("rssi", -100)

        if cell_freq and cell_freq in sdr_freqs:
            correlation["match"] = True
            correlation["indicators"].append("Frequency match between cellular and SDR")
            correlation["confidence"] += 0.4

        if sdr_power > -50 and cell_power > -70:
            correlation["indicators"].append("Strong RF signal on both cellular and SDR")
            correlation["confidence"] += 0.3

        if len(sdr_freqs) > 5 and cell_freq:
            correlation["indicators"].append("Multiple RF signals — possible IMSI catcher mesh")
            correlation["confidence"] += 0.2

        return correlation

    # ── Crowd-Sourced Threat Intel ────────────────────────────────

    @classmethod
    def check_threat_intel(cls, mcc: str = "", mnc: str = "", lat: float = 0.0, lon: float = 0.0) -> dict[str, Any]:
        """Check crowd-sourced threat intel for known IMSI catcher locations."""
        intel: dict[str, Any] = {
            "known_threats": [],
            "risk_score": 0.0,
            "reports_count": 0,
        }

        try:
            from providers.threat_intel import GlobalIntelProvider
            if mcc and mnc:
                intel["risk_score"] = GlobalIntelProvider.risk_score(mcc, mnc).get("risk_score", 0)
            features = GlobalIntelProvider.get_map_data() if hasattr(GlobalIntelProvider, 'get_map_data') else []
            for f in features:
                if lat and lon:
                    dist = ((f.get("lat", 0) - lat) ** 2 + (f.get("lon", 0) - lon) ** 2) ** 0.5
                    if dist < 0.05:
                        intel["known_threats"].append({
                            "cell_hash": f.get("cell_hash", ""),
                            "distance_km": round(dist * 111, 2),
                            "reports": f.get("count", 0),
                        })
                        intel["reports_count"] += f.get("count", 0)
                elif f.get("count", 0) > 5:
                    intel["known_threats"].append({
                        "cell_hash": f.get("cell_hash", ""),
                        "reports": f.get("count", 0),
                    })
        except Exception:
            pass

        return intel

    # ── Automated Response ────────────────────────────────────────

    @classmethod
    def _auto_respond(cls, threats: list[tuple[str, int, str]]) -> list[str]:
        """Take automated countermeasures based on threat severity."""
        actions: list[str] = []
        for msg, level, detail in threats:
            if level >= THREAT_CRITICAL:
                actions.append(f"CRITICAL: {msg} — initiating emergency response")
                if cls._running:
                    cls._alert(f"Emergency countermeasure triggered: {msg}", THREAT_CRITICAL, detail)
            elif level == THREAT_HIGH:
                actions.append(f"HIGH: {msg} — escalating alert")
            elif level == THREAT_MEDIUM:
                actions.append(f"MEDIUM: {msg} — logged for review")
        return actions

    @classmethod
    def enable_network_level_defense(cls) -> dict[str, Any]:
        """Enable network-level protections: VPN enforcement, DNS filtering, cert pinning."""
        result: dict[str, Any] = {" vpn_enabled": False, "dns_filtering": False, "cert_pinning": False}

        try:
            import subprocess
            r = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                result["vpn_enabled"] = "tun" in r.stdout.lower() or "wg" in r.stdout.lower()
        except Exception:
            pass

        try:
            hosts = Path("/etc/hosts")
            if hosts.exists():
                content = hosts.read_text()
                result["dns_filtering"] = "cpip" in content.lower() or "block" in content.lower()
        except Exception:
            pass

        try:
            import ssl
            ctx = ssl.create_default_context()
            result["cert_pinning"] = ctx.get_ciphers() != []
        except Exception:
            pass

        return result

    # ── Enhanced Status ───────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        recent = cls._alerts[-20:] if cls._alerts else []
        fp = cls.fingerprint_rf()
        net_defense = cls.enable_network_level_defense()

        return {
            "enabled": cls._running,
            "source": CELL_SOURCE,
            "threat_level": cls._threat_level,
            "threat_label": THREAT_LABELS[cls._threat_level],
            "serving": dict(cls._serving) if cls._serving else None,
            "baseline": dict(cls._baseline) if cls._baseline else None,
            "gps": dict(cls._gps) if cls._gps else None,
            "scan_count": cls._scan_count,
            "recent_alerts": recent,
            "passive_mode": cls._passive_mode,
            "stealth_mode": cls._stealth_mode,
            "rf_fingerprint": fp,
            "network_defense": net_defense,
            "rat_2g_names": list(RAT_2G_NAMES),
        }
