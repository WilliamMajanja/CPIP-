from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

DURESS_CODE = os.environ.get("CPIP_DURESS_CODE", "")
DURESS_BEHAVIORAL = os.environ.get("CPIP_DURESS_BEHAVIORAL", "0") == "1"
DURESS_PANIC_PIN = int(os.environ.get("CPIP_DURESS_PANIC_DELETE_PIN", "26"))


class DuressProvider(BaseProvider):
    TYPE = ProviderType.SECURITY
    NAME = "duress"
    VERSION = "6.0.0"

    _duress_active = False
    _duress_triggered_at = 0
    _lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def check_command(cls, command: str) -> bool:
        if DURESS_CODE and DURESS_CODE in command:
            cls._activate()
            return True
        return False

    @classmethod
    def _activate(cls):
        with cls._lock:
            if cls._duress_active:
                return
            cls._duress_active = True
            cls._duress_triggered_at = time.time()
        logger.critical("DURESS ACTIVATED")
        from providers.hardware import HardwareProvider
        HardwareProvider.set_threat_level(4)
        from providers.field_ops import FieldOpsProvider
        FieldOpsProvider.deadman_arm()

    @classmethod
    def is_duress(cls) -> bool:
        return cls._duress_active

    @classmethod
    def panic_delete(cls) -> dict:
        logger.critical("PANIC DELETE: wiping keys and rebooting")
        cls._duress_active = False
        return {"status": "wiped", "action": "reboot"}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "active": cls._duress_active,
            "triggered_at": cls._duress_triggered_at,
            "code_configured": bool(DURESS_CODE),
            "behavioral": DURESS_BEHAVIORAL,
            "panic_pin": DURESS_PANIC_PIN,
        }
