from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

MODEM_FW_CHECK = os.environ.get("CPIP_MODEM_FW_CHECK", "1") == "1"
MODEM_FW_MANIFEST = os.environ.get("CPIP_MODEM_FW_MANIFEST", "")
MODEM_NVD_API_KEY = os.environ.get("CPIP_MODEM_NVD_API_KEY", "")


class ModemProvider(BaseProvider):
    TYPE = ProviderType.MODEM
    NAME = "modem"
    VERSION = "6.0.0"

    _fw_info: dict = {}
    _fw_history: list[dict] = []
    _cve_results: list[dict] = []

    @classmethod
    def is_available(cls) -> bool:
        try:
            r = subprocess.run(["mmcli", "-m", "0", "--output=json"],
                               capture_output=True, text=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    @classmethod
    def get_firmware_info(cls) -> dict:
        try:
            r = subprocess.run(["mmcli", "-m", "0", "--output=json"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                modem = data.get("modem", {}).get("generic", {})
                hw = modem.get("hardware", {})
                revision = modem.get("revision", "")
                cls._fw_info = {
                    "manufacturer": modem.get("manufacturer", ""),
                    "model": modem.get("model", ""),
                    "revision": revision,
                    "firmware_version": revision,
                    "hardware": hw.get("revision", ""),
                    "equipment_id": modem.get("equipment-id", "")[:8] + "...",
                }
            else:
                r2 = subprocess.run(["mmcli", "-m", "0", "-S"],
                                    capture_output=True, text=True, timeout=3)
                if r2.returncode == 0:
                    cls._fw_info = {"raw": r2.stdout.strip()[:200]}
        except Exception:
            pass
        return cls._fw_info

    @classmethod
    def check_firmware_integrity(cls) -> dict:
        info = cls.get_firmware_info()
        if not info:
            return {"status": "no_modem", "error": "Cannot query modem firmware"}
        if MODEM_FW_MANIFEST and os.path.exists(MODEM_FW_MANIFEST):
            try:
                manifest = json.loads(Path(MODEM_FW_MANIFEST).read_text())
                known = manifest.get(info.get("revision", ""))
                if known:
                    return {"status": "verified", "expected": known, "actual": info.get("revision", "")}
            except Exception:
                pass
        return {"status": "unknown", "firmware": info}

    @classmethod
    def scan_cves(cls) -> list[dict]:
        if not MODEM_NVD_API_KEY:
            return [{"error": "No NVD API key configured"}]
        info = cls.get_firmware_info()
        model = info.get("model", "")
        if not model:
            return []
        try:
            import urllib.request
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={model}&apiKey={MODEM_NVD_API_KEY}"
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                vulns = data.get("vulnerabilities", [])
                cls._cve_results = [
                    {"cve": v["cve"]["id"], "description": v["cve"]["descriptions"][0]["value"][:200]}
                    for v in vulns[:10]
                ]
        except Exception as e:
            cls._cve_results = [{"error": str(e)}]
        return cls._cve_results

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "firmware": cls._fw_info,
            "fw_history_count": len(cls._fw_history),
            "cves_found": len(cls._cve_results),
            "cves": cls._cve_results[:5] if cls._cve_results else [],
        }
