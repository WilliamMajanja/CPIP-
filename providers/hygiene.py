from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

HYGIENE_SCAN = os.environ.get("CPIP_HYGIENE_SCAN", "1") == "1"
HYGIENE_FS_WATCH = os.environ.get("CPIP_HYGIENE_FS_WATCH", "/etc,/usr/lib/systemd")
HYGIENE_STALKERWARE_DB = os.environ.get("CPIP_HYGIENE_STALKERWARE_DB", "")

STALKERWARE_SIGNATURES = {
    "process_names": [
        "mspy", "flexispy", "cerberus", "sendstealth", "highster",
        "spyera", "thetruthspy", "cocospy", "umobix", "xnspy",
        "phoneworx", "mobile-spy", "spyzie", "eyezy",
    ],
    "package_names": [
        "com.mspy", "com.flexispy", "com.cerberus", "com.highster",
        "com.spyera", "com.cocospy", "com.umobix",
    ],
}

STALKERWARE_DB_BUILTIN = json.dumps(STALKERWARE_SIGNATURES)


class HygieneProvider(BaseProvider):
    TYPE = ProviderType.HYGIENE
    NAME = "hygiene"
    VERSION = "6.0.3"

    _scan_results: dict[str, Any] = {}
    _last_scan = 0
    _alerts: list[dict] = []
    _fs_manifest: dict[str, str] = {}

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        if HYGIENE_SCAN:
            cls._load_fs_manifest()

    @classmethod
    def _load_fs_manifest(cls):
        for path in HYGIENE_FS_WATCH.split(","):
            path = path.strip()
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, "rb") as fh:
                                cls._fs_manifest[fpath] = hashlib.sha256(fh.read()).hexdigest()
                        except Exception:
                            pass

    @classmethod
    def scan_processes(cls) -> list[dict]:
        found = []
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                lower = line.lower()
                for sig in STALKERWARE_SIGNATURES["process_names"]:
                    if sig in lower:
                        found.append({"process": line.split()[-1] if line.split() else "?", "signature": sig})
        except Exception:
            pass
        return found

    @classmethod
    def scan_file_integrity(cls) -> list[dict]:
        changes = []
        for path in HYGIENE_FS_WATCH.split(","):
            path = path.strip()
            if not os.path.isdir(path):
                continue
            for root, dirs, files in os.walk(path):
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "rb") as fh:
                            current = hashlib.sha256(fh.read()).hexdigest()
                        stored = cls._fs_manifest.get(fpath)
                        if stored and current != stored:
                            changes.append({"file": fpath, "status": "modified"})
                        elif not stored:
                            changes.append({"file": fpath, "status": "new"})
                    except Exception:
                        pass
        return changes

    @classmethod
    def scan_diag_ports(cls) -> list[dict]:
        ports = []
        diag_devices = ["/dev/smd0", "/dev/smd1", "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/qcqmi0"]
        for dev in diag_devices:
            if os.path.exists(dev):
                ports.append({"device": dev, "status": "open"})
        return ports

    @classmethod
    def scan_full(cls) -> dict:
        processes = cls.scan_processes()
        filesystem = cls.scan_file_integrity()
        diag = cls.scan_diag_ports()
        cls._scan_results = {
            "timestamp": time.time(),
            "processes": processes,
            "filesystem_changes": filesystem,
            "diag_ports": diag,
            "summary": {
                "stalkerware": len(processes),
                "fs_changes": len(filesystem),
                "open_diag": len(diag),
            },
        }
        if processes:
            cls._alerts.append({"time": time.time(), "type": "stalkerware", "count": len(processes)})
        return cls._scan_results

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": HYGIENE_SCAN,
            "last_scan": cls._last_scan,
            "results": cls._scan_results.get("summary", {}) if cls._scan_results else None,
            "alerts": cls._alerts[-5:] if cls._alerts else [],
            "fs_watched": HYGIENE_FS_WATCH,
        }

    @classmethod
    def quarantine(cls, process_name: str) -> dict:
        try:
            result = subprocess.run(["killall", "-STOP", process_name],
                                    capture_output=True, text=True, timeout=5)
            return {"process": process_name, "action": "stopped", "result": result.returncode == 0}
        except Exception as e:
            return {"error": str(e)}
