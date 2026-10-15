from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

try:
    GPIO_PIN_MAP = json.loads(os.environ.get("CPIP_GPIO_PIN_MAP",
        '{"led_green":17,"led_amber":27,"led_red":22,"buzzer":23,"relay_faraday":24,"radio_kill":25}'))
    if not isinstance(GPIO_PIN_MAP, dict) or any(
        not isinstance(pin, int) or not 0 <= pin <= 27 for pin in GPIO_PIN_MAP.values()
    ):
        raise ValueError("GPIO pin map must map names to BCM pins 0..27")
except (TypeError, ValueError, json.JSONDecodeError) as exc:
    logger.warning("Invalid CPIP_GPIO_PIN_MAP; hardware outputs disabled: %s", exc)
    GPIO_PIN_MAP = {}
GPIO_WATCHDOG = os.environ.get("CPIP_GPIO_WATCHDOG", "0") == "1"


class HardwareProvider(BaseProvider):
    TYPE = ProviderType.HARDWARE
    NAME = "hardware"
    VERSION = "7.0.0"

    _gpio_initialized = False
    _gpio = None
    _watchdog_active = False
    _lock = threading.Lock()
    _watchdog_thread: threading.Thread | None = None
    _watchdog_last_kick = 0.0

    @classmethod
    def is_available(cls) -> bool:
        try:
            import RPi  # noqa: F401
            return os.path.exists("/dev/gpiomem") or os.path.exists("/sys/class/gpio")
        except ImportError:
            return False

    @classmethod
    def _init_gpio(cls):
        if cls._gpio_initialized:
            return
        try:
            import RPi.GPIO as GPIO
            cls._gpio = GPIO
            GPIO.setmode(GPIO.BCM)
            for pin in set(GPIO_PIN_MAP.values()):
                GPIO.setup(pin, GPIO.OUT, initial=GPIO.LOW)
            cls._gpio_initialized = True
        except Exception as e:
            logger.debug("GPIO init: %s", e)

    @classmethod
    def set_threat_level(cls, level: int):
        cls._init_gpio()
        pins = GPIO_PIN_MAP
        if cls._gpio is None or not pins:
            return
        def output(name: str, value: int):
            pin = pins.get(name)
            if pin is not None:
                cls._gpio.output(pin, value)
        if level >= 4:
            output("led_red", 1)
            output("led_amber", 0)
            output("led_green", 0)
            output("buzzer", 1)
            output("relay_faraday", 1)
            output("radio_kill", 1)
        elif level == 3:
            output("led_red", 1)
            output("led_amber", 0)
            output("led_green", 0)
            output("buzzer", 1)
        elif level == 2:
            output("led_red", 0)
            output("led_amber", 1)
            output("led_green", 0)
            output("buzzer", 0)
        elif level == 1:
            output("led_red", 0)
            output("led_amber", 0)
            output("led_green", 0)
            output("buzzer", 0)
        else:
            output("led_green", 1)
            output("led_red", 0)
            output("led_amber", 0)
            output("buzzer", 0)

    @classmethod
    def test_pin(cls, pin: int, duration: float = 0.5):
        if not isinstance(pin, int) or not 0 <= pin <= 27:
            return {"error": "Pin must be a BCM GPIO number from 0 to 27"}
        if not 0 < duration <= 5:
            return {"error": "Duration must be between 0 and 5 seconds"}
        cls._init_gpio()
        if cls._gpio:
            cls._gpio.output(pin, 1)
            time.sleep(duration)
            cls._gpio.output(pin, 0)
            return {"tested": pin, "ok": True}
        return {"error": "GPIO not available"}

    @classmethod
    def enable_watchdog(cls) -> tuple[int, dict[str, Any]]:
        """Report unsupported rather than claiming a process-local failsafe works."""
        cls._init_gpio()
        if cls._gpio is None or "radio_kill" not in GPIO_PIN_MAP:
            return 503, {"error": "Watchdog unavailable: GPIO and radio_kill pin are required", "active": False}
        return 501, {"error": "Hardware watchdog backend is not configured", "active": False}

    @classmethod
    def disable_watchdog(cls) -> tuple[int, dict[str, Any]]:
        cls._watchdog_active = False
        return 200, {"status": "watchdog_disabled", "active": False}

    @classmethod
    def watchdog_status(cls) -> dict[str, Any]:
        return {
            "active": cls._watchdog_active,
            "available": cls.is_available() and "radio_kill" in GPIO_PIN_MAP,
            "last_kick": cls._watchdog_last_kick or None,
            "mode": "unsupported",
        }

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "available": cls.is_available(),
            "initialized": cls._gpio_initialized,
            "pin_map": GPIO_PIN_MAP,
            "watchdog": cls._watchdog_active,
            "watchdog_status": cls.watchdog_status(),
        }
