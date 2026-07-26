from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

I2C_BUS = int(os.environ.get("CPIP_SENSOR_I2C_BUS", "1"))
SENSOR_ACCEL = os.environ.get("CPIP_SENSOR_ACCEL", "1") == "1"
SENSOR_LIGHT = os.environ.get("CPIP_SENSOR_LIGHT", "1") == "1"
SENSOR_MIC = os.environ.get("CPIP_SENSOR_MIC", "1") == "1"
SENSOR_MAG = os.environ.get("CPIP_SENSOR_MAG", "1") == "1"
SENSOR_THERMAL = os.environ.get("CPIP_SENSOR_THERMAL", "0") == "1"


class SensorProvider(BaseProvider):
    TYPE = ProviderType.SENSOR
    NAME = "sensors"
    VERSION = "6.0.0"

    _running = False
    _thread: threading.Thread | None = None
    _lock = threading.Lock()
    _readings: dict[str, Any] = {}
    _alerts: list[dict] = []
    _scorer_callback = None

    @classmethod
    def is_available(cls) -> bool:
        try:
            import smbus2
            bus = smbus2.SMBus(I2C_BUS)
            bus.close()
            return True
        except Exception:
            return False

    @classmethod
    def set_scorer_callback(cls, fn):
        cls._scorer_callback = fn

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._sensor_loop, daemon=True)
        cls._thread.start()
        logger.info("SensorProvider started")

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _sensor_loop(cls):
        while cls._running:
            try:
                cls._read_all()
                cls._analyze()
            except Exception as e:
                logger.debug("Sensor error: %s", e)
            time.sleep(2)

    @classmethod
    def _read_all(cls):
        import math
        readings = {"timestamp": time.time()}
        try:
            import smbus2
            bus = smbus2.SMBus(I2C_BUS)

            # ADXL345 accelerometer (0x53)
            if SENSOR_ACCEL:
                try:
                    data = bus.read_i2c_block_data(0x53, 0x32, 6)
                    x = cls._twos_comp(data[0] | (data[1] << 8), 16) * 0.004
                    y = cls._twos_comp(data[2] | (data[3] << 8), 16) * 0.004
                    z = cls._twos_comp(data[4] | (data[5] << 8), 16) * 0.004
                    readings["accel"] = {"x": x, "y": y, "z": z}
                    readings["accel_magnitude"] = math.sqrt(x * x + y * y + z * z)
                except Exception:
                    pass

            # BH1750 light sensor (0x23)
            if SENSOR_LIGHT:
                try:
                    data = bus.read_i2c_block_data(0x23, 0x10, 2)
                    lux = (data[0] << 8 | data[1]) / 1.2
                    readings["light_lux"] = lux
                except Exception:
                    pass

            # MPU9250 magnetometer (0x0C)
            if SENSOR_MAG:
                try:
                    data = bus.read_i2c_block_data(0x0C, 0x03, 6)
                    mx = cls._twos_comp(data[0] | (data[1] << 8), 16) * 0.15
                    my = cls._twos_comp(data[2] | (data[3] << 8), 16) * 0.15
                    mz = cls._twos_comp(data[4] | (data[5] << 8), 16) * 0.15
                    readings["mag"] = {"x": mx, "y": my, "z": mz}
                    readings["mag_strength"] = math.sqrt(mx * mx + my * my + mz * mz)
                except Exception:
                    pass

            bus.close()
        except Exception:
            pass

        with cls._lock:
            cls._readings = readings

    @classmethod
    def _twos_comp(cls, val: int, bits: int) -> int:
        if val & (1 << (bits - 1)):
            val -= 1 << bits
        return val

    @classmethod
    def _analyze(cls):
        r = cls._readings
        ts = time.time()

        # Accelerometer stillness detection
        if "accel_magnitude" in r:
            mag = r["accel_magnitude"]
            if hasattr(cls, "_prev_mag") and abs(mag - cls._prev_mag) < 0.05:
                cls._still_seconds = getattr(cls, "_still_seconds", 0) + 2
            else:
                cls._still_seconds = 0
            cls._prev_mag = mag

        # Light + stillness + no cell → Faraday bag
        if r.get("light_lux", 100) < 5 and getattr(cls, "_still_seconds", 0) > 30:
            cls._alert("Possible Faraday bag: dark + still + prolonged", 0.7, "sensor_faraday")

        # Magnetometer: strong field → surveillance van
        if r.get("mag_strength", 0) > 50:
            cls._alert("Strong magnetic field >50uT: possible surveillance van proximity", 0.4, "sensor_mag")

        # Ultrasonic detection via MEMS mic (placeholder)
        if SENSOR_MIC:
            pass

    @classmethod
    def _alert(cls, message: str, confidence: float, heuristic: str):
        entry = {"time": time.time(), "message": message, "confidence": confidence, "heuristic": heuristic}
        cls._alerts.append(entry)
        if len(cls._alerts) > 50:
            cls._alerts = cls._alerts[-50:]
        if cls._scorer_callback:
            cls._scorer_callback("sensors", heuristic, confidence, message)

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        with cls._lock:
            return {
                "running": cls._running,
                "available": cls.is_available(),
                "current": dict(cls._readings) if cls._readings else None,
                "alerts": cls._alerts[-10:] if cls._alerts else [],
            }

    @classmethod
    def calibrate(cls) -> dict:
        cls._readings = {}
        cls._alerts.clear()
        return {"status": "calibrated"}
