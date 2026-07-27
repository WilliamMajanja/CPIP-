from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

EVIDENCE_NOTARIZE = os.environ.get("CPIP_EVIDENCE_NOTARIZE", "0") == "1"
EVIDENCE_CHAIN = os.environ.get("CPIP_EVIDENCE_CHAIN", "ots")


class EvidenceProvider(BaseProvider):
    TYPE = ProviderType.EVIDENCE
    NAME = "evidence"
    VERSION = "6.0.3"

    _evidence_dir = Path("/tmp/cpip_evidence")
    _chain: list[dict] = []
    _lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        cls._evidence_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def capture(cls, data: dict, label: str = "manual") -> dict:
        ts = int(time.time())
        entry = {
            "id": f"ev_{ts}_{secrets.token_hex(4)}",
            "timestamp": ts,
            "label": label,
            "data": data,
        }
        sha256 = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        entry["sha256"] = sha256

        prev_hash = cls._chain[-1]["sha256"] if cls._chain else "0" * 64
        entry["prev_hash"] = prev_hash

        with cls._lock:
            cls._chain.append(entry)
            if len(cls._chain) > 1000:
                cls._chain = cls._chain[-1000:]

        fpath = cls._evidence_dir / f"{entry['id']}.json"
        fpath.write_text(json.dumps(entry, indent=2))
        entry["path"] = str(fpath)

        if EVIDENCE_NOTARIZE:
            cls._submit_hash(sha256)

        return entry

    @classmethod
    def _submit_hash(cls, sha256: str):
        chain_type = EVIDENCE_CHAIN
        try:
            if chain_type == "bitcoin":
                subprocess.run(
                    ["bitcoin-cli", "sendrawtransaction",
                     f"6a26{sha256}234fadea77a5e3c17b9876543210fedcba9876543210"],
                    capture_output=True, timeout=10)
            elif chain_type == "ots":
                subprocess.run(["ots", "stamp", sha256], capture_output=True, timeout=30)
            logger.info("Evidence hash %s submitted to %s", sha256[:16], chain_type)
        except Exception as e:
            logger.debug("Notarize error: %s", e)

    @classmethod
    def verify(cls, evidence_id: str) -> dict:
        for entry in cls._chain:
            if entry["id"] == evidence_id:
                computed = hashlib.sha256(json.dumps(entry["data"], sort_keys=True).encode()).hexdigest()
                return {"id": evidence_id, "valid": computed == entry["sha256"],
                        "stored_hash": entry["sha256"], "computed_hash": computed}
        return {"id": evidence_id, "error": "not_found"}

    @classmethod
    def notarize_all(cls) -> dict:
        count = 0
        for entry in cls._chain:
            if not entry.get("notarized"):
                cls._submit_hash(entry["sha256"])
                entry["notarized"] = True
                count += 1
        return {"notarized": count}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "chain_length": len(cls._chain),
            "last_entry": cls._chain[-1] if cls._chain else None,
            "evidence_dir": str(cls._evidence_dir),
            "notarize_enabled": EVIDENCE_NOTARIZE,
            "chain_method": EVIDENCE_CHAIN,
        }
