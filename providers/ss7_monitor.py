from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

SS7_MONITOR = os.environ.get("CPIP_SS7_MONITOR", "0") == "1"
SS7_IFACE = os.environ.get("CPIP_SS7_IFACE", "lo")
SS7_SIGFW_SOCKET = os.environ.get("CPIP_SS7_SIGFW_SOCKET", "")
SS7_BLOCK_ATI = os.environ.get("CPIP_SS7_BLOCK_ATI", "1") == "1"


class SS7Monitor(BaseProvider):
    TYPE = ProviderType.SS7
    NAME = "ss7_monitor"
    VERSION = "6.0.0"

    _running = False
    _thread: threading.Thread | None = None
    _events: list[dict] = []
    _alerts: list[dict] = []

    MAP_OPCODES = {
        "AnyTimeInterrogation": "ATI",
        "ProvideSubscriberInfo": "PSI",
        "SendRoutingInfoForSM": "SRI_SM",
        "ForwardSM": "FWD_SM",
        "UpdateLocation": "UL",
        "CancelLocation": "CL",
    }

    @classmethod
    def is_available(cls) -> bool:
        return SS7_MONITOR

    @classmethod
    def start(cls):
        if not SS7_MONITOR or cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._monitor_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def _monitor_loop(cls):
        while cls._running:
            try:
                cls._capture_packets()
            except Exception as e:
                logger.debug("SS7 capture error: %s", e)
            time.sleep(10)

    @classmethod
    def _capture_packets(cls):
        if SS7_SIGFW_SOCKET:
            cls._read_sigfw()
        import subprocess
        result = subprocess.run(
            ["tcpdump", "-i", SS7_IFACE, "-c", "10", "-nn", "-X", "port", "2905", "or", "port", "3868"],
            capture_output=True, text=True, timeout=5, check=False)
        if result.stdout:
            cls._events.append({
                "time": time.time(),
                "source": "pcap",
                "raw_length": len(result.stdout),
                "summary": result.stdout[:200],
            })

    @classmethod
    def _read_sigfw(cls):
        try:
            import socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(SS7_SIGFW_SOCKET)
            data = sock.recv(4096)
            if data:
                cls._alerts.append({
                    "time": time.time(),
                    "source": "sigfw",
                    "data": data.decode(errors="replace")[:500],
                })
            sock.close()
        except Exception:
            pass

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": SS7_MONITOR,
            "running": cls._running,
            "events": len(cls._events),
            "alerts": len(cls._alerts),
            "recent_alerts": cls._alerts[-5:] if cls._alerts else [],
        }

    @classmethod
    def get_log(cls, lines: int = 20) -> list[dict]:
        return cls._events[-lines:] if cls._events else []
