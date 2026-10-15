from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

CARRIER_API_ENABLED = os.environ.get("CPIP_CARRIER_API", "0") == "1"
CARRIER_ATT_KEY = os.environ.get("CPIP_CARRIER_ATT_FRAUD_KEY", "")
CARRIER_TMO_KEY = os.environ.get("CPIP_CARRIER_TMO_PARTNER_KEY", "")
CARRIER_VZ_KEY = os.environ.get("CPIP_CARRIER_VZ_EDGE_KEY", "")


class CarrierProvider(BaseProvider):
    TYPE = ProviderType.INTELLIGENCE
    NAME = "carrier"
    VERSION = "7.0.0"

    _events: list[dict] = []
    _webhook_registered = False
    _webhook_url = ""

    WEBHOOK_HANDLERS = {
        "sim_swap": lambda e: ("THREAT_HIGH", f"SIM swap detected: {e.get('iccid','?')}"),
        "port_request": lambda e: ("THREAT_HIGH", f"Port request for {e.get('msisdn','?')}"),
        "imsi_change": lambda e: ("THREAT_MEDIUM", f"IMSI changed: {e.get('old_imsi','?')} → {e.get('new_imsi','?')}"),
    }

    @classmethod
    def is_available(cls) -> bool:
        return bool(CARRIER_ATT_KEY or CARRIER_TMO_KEY or CARRIER_VZ_KEY)

    @classmethod
    def register_webhook(cls, url: str = "") -> dict:
        url = str(url or "").strip()
        if url and not url.startswith(("https://", "http://")):
            return {"error": "Webhook URL must use http:// or https://"}
        cls._webhook_registered = True
        cls._webhook_url = url
        carriers = []
        if CARRIER_ATT_KEY:
            carriers.append("att")
        if CARRIER_TMO_KEY:
            carriers.append("tmo")
        if CARRIER_VZ_KEY:
            carriers.append("vz")
        return {"registered": True, "url": url or None, "carriers": carriers,
                "delivery": "local webhook receiver; carrier registration requires carrier credentials"}

    @classmethod
    def process_webhook_event(cls, body: dict) -> dict:
        if not isinstance(body, dict):
            return {"processed": False, "error": "Webhook body must be an object"}
        event_type = body.get("event", "")
        handler = cls.WEBHOOK_HANDLERS.get(event_type)
        if handler:
            severity, message = handler(body)
            cls._events.append({
                "time": time.time(),
                "type": event_type,
                "severity": severity,
                "message": message,
                "detail": body,
            })
            return {"processed": True, "alert": message}
        return {"processed": False, "error": f"Unknown event: {event_type}"}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
                "enabled": CARRIER_API_ENABLED,
                "webhook_registered": cls._webhook_registered,
                "webhook_url": cls._webhook_url or None,
            "carriers": {
                "att": bool(CARRIER_ATT_KEY),
                "tmo": bool(CARRIER_TMO_KEY),
                "vz": bool(CARRIER_VZ_KEY),
            },
            "events_count": len(cls._events),
            "recent_events": cls._events[-5:] if cls._events else [],
        }

    @classmethod
    def get_history(cls) -> list[dict]:
        return list(cls._events)
