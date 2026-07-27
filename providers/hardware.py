from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

GPIO_PIN_MAP = json.loads(os.environ.get("CPIP_GPIO_PIN_MAP",
    '{"led_green":17,"led_amber":27,"led_red":22,"buzzer":23,"relay_faraday":24,"radio_kill":25}'))
GPIO_WATCHDOG = os.environ.get("CPIP_GPIO_WATCHDOG", "1") == "1"


class HardwareProvider(BaseProvider):
    TYPE = ProviderType.HARDWARE
    NAME = "hardware"
    VERSION = "6.0.3"

    _gpio_initialized = False
    _gpio = None
    _watchdog_active = GPIO_WATCHDOG
    _lock = threading.Lock()

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
            for pin in GPIO_PIN_MAP.values():
                GPIO.setup(pin, GPIO.OUT, initial=GPIO.LOW)
            cls._gpio_initialized = True
        except Exception as e:
            logger.debug("GPIO init: %s", e)

    @classmethod
    def set_threat_level(cls, level: int):
        cls._init_gpio()
        if cls._gpio is None:
            return
        pins = GPIO_PIN_MAP
        if level >= 4:
            cls._gpio.output(pins.get("led_red"), 1)
            cls._gpio.output(pins.get("led_amber"), 0)
            cls._gpio.output(pins.get("led_green"), 0)
            cls._gpio.output(pins.get("buzzer"), 1)
            cls._gpio.output(pins.get("relay_faraday"), 1)
            cls._gpio.output(pins.get("radio_kill"), 1)
        elif level == 3:
            cls._gpio.output(pins.get("led_red"), 1)
            cls._gpio.output(pins.get("led_amber"), 0)
            cls._gpio.output(pins.get("led_green"), 0)
            cls._gpio.output(pins.get("buzzer"), 1)
        elif level == 2:
            cls._gpio.output(pins.get("led_red"), 0)
            cls._gpio.output(pins.get("led_amber"), 1)
            cls._gpio.output(pins.get("led_green"), 0)
            cls._gpio.output(pins.get("buzzer"), 0)
        elif level == 1:
            cls._gpio.output(pins.get("led_red"), 0)
            cls._gpio.output(pins.get("led_amber"), 0)
            cls._gpio.output(pins.get("led_green"), 0)
            cls._gpio.output(pins.get("buzzer"), 0)
        else:
            cls._gpio.output(pins.get("led_green"), 1)
            cls._gpio.output(pins.get("led_red"), 0)
            cls._gpio.output(pins.get("led_amber"), 0)
            cls._gpio.output(pins.get("buzzer"), 0)

    @classmethod
    def test_pin(cls, pin: int, duration: float = 0.5):
        cls._init_gpio()
        if cls._gpio:
            cls._gpio.output(pin, 1)
            time.sleep(duration)
            cls._gpio.output(pin, 0)
            return {"tested": pin, "ok": True}
        return {"error": "GPIO not available"}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "available": cls.is_available(),
            "initialized": cls._gpio_initialized,
            "pin_map": GPIO_PIN_MAP,
            "watchdog": cls._watchdog_active,
        }
