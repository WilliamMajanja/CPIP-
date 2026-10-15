from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import subprocess
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

AIRGAP_CAMERA = os.environ.get("CPIP_AIRGAP_CAMERA", "")
AIRGAP_AUDIO_DEVICE = os.environ.get("CPIP_AIRGAP_AUDIO_DEVICE", "")
AIRGAP_NFC_DEVICE = os.environ.get("CPIP_AIRGAP_NFC_DEVICE", "")


class AirGapProvider(BaseProvider):
    TYPE = ProviderType.RADIO
    NAME = "airgap"
    VERSION = "7.0.0"

    _messages_sent = 0
    _messages_received = 0

    MORSE_MAP = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
        "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
        "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
        "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
        "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
        "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
        "3": "...--", "4": "....-", "5": ".....", "6": "-....",
        "7": "--...", "8": "---..", "9": "----.",
    }

    @classmethod
    def is_available(cls) -> bool:
        return bool(AIRGAP_CAMERA or AIRGAP_AUDIO_DEVICE or AIRGAP_NFC_DEVICE)

    @classmethod
    def qr_send(cls, data: str) -> dict:
        import base64
        if not isinstance(data, str) or not data:
            return {"error": "QR payload must be a non-empty string"}
        chunks = [data[i:i + 2000] for i in range(0, len(data), 2000)]
        if len(chunks) > 1:
            return {"chunks": len(chunks), "total_bytes": len(data),
                    "frames": [base64.b64encode(c.encode()).decode() for c in chunks],
                    "status": "encoded", "note": "Display each frame in order; framing metadata is required by the receiver"}
        qr_data = base64.b64encode(data.encode()).decode()
        result = {"qr_data": qr_data, "qr_data_length": len(qr_data), "chunks": 1,
                  "status": "encoded"}
        try:
            import qrcode
            import io
            import base64 as b64
            image = qrcode.make(qr_data)
            output = io.BytesIO()
            image.save(output, format="PNG")
            result["png_base64"] = b64.b64encode(output.getvalue()).decode()
            result["status"] = "ready_to_display"
        except ImportError:
            result["display_backend"] = "unavailable; install the optional qrcode package to create a QR image"
        return result

    @classmethod
    def audio_tx(cls, message: str) -> dict:
        if not AIRGAP_AUDIO_DEVICE:
            return {"error": "No audio device configured"}
        return {"error": "Audio transmit backend is not implemented; no audio was emitted",
                "device": AIRGAP_AUDIO_DEVICE, "transmitted": False}

    @classmethod
    def nfc_pair(cls, peer: str) -> dict:
        if not AIRGAP_NFC_DEVICE:
            return {"error": "No NFC device configured"}
        return {"error": "NFC pairing backend is not implemented; no key was exchanged",
                "peer": peer, "paired": False}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "camera": bool(AIRGAP_CAMERA),
            "audio_device": bool(AIRGAP_AUDIO_DEVICE),
            "nfc_device": bool(AIRGAP_NFC_DEVICE),
            "messages_sent": cls._messages_sent,
            "modes": ["qr", "audio_fsk", "led_morse", "nfc"],
        }
