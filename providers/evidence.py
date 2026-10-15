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
    VERSION = "7.0.0"

    _evidence_dir = Path(os.environ.get("CPIP_EVIDENCE_DIR", "/tmp/cpip_evidence"))
    _chain: list[dict] = []
    _lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        cls._evidence_dir.mkdir(parents=True, exist_ok=True)
        entries = []
        for path in cls._evidence_dir.glob("ev_*.json"):
            try:
                entries.append(json.loads(path.read_text()))
            except (OSError, json.JSONDecodeError):
                logger.warning("Skipping unreadable evidence entry %s", path)
        cls._chain = sorted(entries, key=lambda e: e.get("timestamp", 0))[-10000:]

    @classmethod
    def capture(cls, data: dict, label: str = "manual") -> dict:
        ts = int(time.time())
        entry = {
            "id": f"ev_{ts}_{secrets.token_hex(4)}",
            "timestamp": ts,
            "label": label,
            "data": data,
        }
        canonical_data = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        sha256 = hashlib.sha256(canonical_data).hexdigest()
        entry["sha256"] = sha256
        entry["prev_hash"] = cls._chain[-1].get("chain_hash", cls._chain[-1].get("sha256", "0" * 64)) if cls._chain else "0" * 64
        chain_material = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        entry["chain_hash"] = hashlib.sha256(chain_material).hexdigest()

        with cls._lock:
            cls._chain.append(entry)
        fpath = cls._evidence_dir / f"{entry['id']}.json"
        temp_path = fpath.with_suffix(".json.tmp")
        temp_path.write_text(json.dumps(entry, indent=2))
        os.replace(temp_path, fpath)
        entry["path"] = str(fpath)

        if EVIDENCE_NOTARIZE:
            cls._submit_hash(entry["chain_hash"])

        return entry

    @classmethod
    def _submit_hash(cls, sha256: str) -> dict:
        chain_type = EVIDENCE_CHAIN
        try:
            if chain_type != "ots":
                return {"status": "unsupported", "chain": chain_type,
                        "error": "Only OpenTimestamps submission is implemented"}
            digest_path = cls._evidence_dir / f"{sha256}.sha256"
            digest_path.write_text(sha256 + "\n")
            result = subprocess.run(["ots", "stamp", str(digest_path)],
                                    capture_output=True, text=True, timeout=30, check=False)
            if result.returncode:
                return {"status": "failed", "chain": chain_type,
                        "error": result.stderr.strip() or "ots stamp failed"}
            logger.info("Evidence hash %s submitted to %s", sha256[:16], chain_type)
            return {"status": "submitted", "chain": chain_type}
        except Exception as e:
            logger.debug("Notarize error: %s", e)
            return {"status": "failed", "chain": chain_type, "error": str(e)}

    @classmethod
    def verify(cls, evidence_id: str) -> dict:
        for entry in cls._chain:
            if entry["id"] == evidence_id:
                computed = hashlib.sha256(json.dumps(entry["data"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                chain_copy = {k: v for k, v in entry.items() if k not in ("chain_hash", "path", "notarized")}
                computed_chain = hashlib.sha256(json.dumps(chain_copy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                valid = computed == entry["sha256"] and computed_chain == entry.get("chain_hash", computed_chain)
                return {"id": evidence_id, "valid": valid,
                        "stored_hash": entry["sha256"], "computed_hash": computed}
        return {"id": evidence_id, "error": "not_found"}

    @classmethod
    def notarize(cls, evidence_id: str) -> dict:
        """Submit a single chain entry's hash for notarization (RFC-0022)."""
        for entry in cls._chain:
            if entry["id"] == evidence_id:
                result = cls._submit_hash(entry.get("chain_hash", entry["sha256"]))
                entry["notarized"] = result.get("status") == "submitted"
                return {"id": evidence_id, **result, "sha256": entry["sha256"]}
        return {"id": evidence_id, "error": "not_found"}

    @classmethod
    def notarize_all(cls) -> dict:
        count = 0
        for entry in cls._chain:
            if not entry.get("notarized"):
                result = cls._submit_hash(entry.get("chain_hash", entry["sha256"]))
                entry["notarized"] = result.get("status") == "submitted"
                count += int(entry["notarized"])
        return {"notarized": count, "requested": len(cls._chain)}

    @classmethod
    def get_chain(cls) -> dict:
        return {"count": len(cls._chain), "chain": [
            {"id": e.get("id"), "timestamp": e.get("timestamp"),
             "label": e.get("label"), "sha256": e.get("sha256"),
             "prev_hash": e.get("prev_hash"), "chain_hash": e.get("chain_hash"),
             "notarized": e.get("notarized", False)} for e in cls._chain
        ]}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "chain_length": len(cls._chain),
            "last_entry": cls._chain[-1] if cls._chain else None,
            "evidence_dir": str(cls._evidence_dir),
            "notarize_enabled": EVIDENCE_NOTARIZE,
            "chain_method": EVIDENCE_CHAIN,
        }
