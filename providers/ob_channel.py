from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

OB_BT_MESH = os.environ.get("CPIP_OB_BT_MESH", "0") == "1"
OB_NFC = os.environ.get("CPIP_OB_NFC", "0") == "1"
OB_AUDIO = os.environ.get("CPIP_OB_AUDIO", "0") == "1"
OB_LIFI = os.environ.get("CPIP_OB_LIFI", "0") == "1"
OB_FAILOVER = os.environ.get("CPIP_OB_FAILOVER", "1") == "1"


class OBChannelProvider(BaseProvider):
    TYPE = ProviderType.RADIO
    NAME = "ob_channel"
    VERSION = "6.0.0"

    _channels: dict[str, bool] = {"bt": False, "nfc": False, "audio": False, "lifi": False}
    _messages_sent = 0
    _messages_received = 0

    CHANNELS = [
        {"name": "bt", "desc": "Bluetooth Mesh", "bitrate": "10Kbps", "range": "10m"},
        {"name": "nfc", "desc": "NFC Tap", "bitrate": "1KB/tap", "range": "contact"},
        {"name": "audio", "desc": "Audio FSK Modem", "bitrate": "50bps", "range": "2m"},
        {"name": "lifi", "desc": "LiFi Camera Flash", "bitrate": "100bps", "range": "5m"},
    ]

    @classmethod
    def is_available(cls) -> bool:
        return OB_BT_MESH or OB_NFC or OB_AUDIO or OB_LIFI

    @classmethod
    def send(cls, channel: str, peer: str, message: str) -> dict:
        available = {
            "bt": OB_BT_MESH, "nfc": OB_NFC, "audio": OB_AUDIO, "lifi": OB_LIFI,
        }
        if not available.get(channel, False):
            return {"error": f"Channel {channel} not enabled"}
        cls._messages_sent += 1
        logger.info("OB %s → %s: %d bytes", channel, peer, len(message))
        return {"channel": channel, "peer": peer, "sent": True, "bytes": len(message)}

    @classmethod
    def receive(cls, channel: str) -> dict | None:
        if channel == "audio" and OB_AUDIO:
            return {"channel": "audio", "message": "SAMPLE_AUDIO_RX", "received": True}
        return None

    @classmethod
    def list_channels(cls) -> list[dict]:
        available = {
            "bt": OB_BT_MESH, "nfc": OB_NFC, "audio": OB_AUDIO, "lifi": OB_LIFI,
        }
        return [
            {**ch, "enabled": available.get(ch["name"], False)}
            for ch in cls.CHANNELS
        ]

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "channels": cls.list_channels(),
            "messages_sent": cls._messages_sent,
            "messages_received": cls._messages_received,
            "failover": OB_FAILOVER,
        }
