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

THREAT_NONE = 0
THREAT_LOW = 1
THREAT_MEDIUM = 2
THREAT_HIGH = 3
THREAT_CRITICAL = 4
THREAT_LABELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class CellularProvider(BaseProvider):
    TYPE = ProviderType.CELLULAR
    NAME = "cellular"
    VERSION = "6.0.0"

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

    _mm = None

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

        # 5. 2G degradation
        if "2G" in rat:
            threats.append(("RAT is 2G — no encryption", THREAT_HIGH,
                            "Device may be forced to insecure mode"))

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


AntiStingrayV2 = CellularProvider
