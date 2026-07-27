from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

MESH_ATTACK_DETECT = os.environ.get("CPIP_MESH_ATTACK_DETECT", "1") == "1"
MESH_SYBIL_THRESHOLD = int(os.environ.get("CPIP_MESH_SYBIL_THRESHOLD", "5"))
MESH_ECLIPSE_THRESHOLD = float(os.environ.get("CPIP_MESH_ECLIPSE_THRESHOLD", "0.8"))
MESH_DISAPPEAR_HOURS = int(os.environ.get("CPIP_MESH_DISAPPEAR_HOURS", "48"))


class MeshSecurityProvider(BaseProvider):
    TYPE = ProviderType.SECURITY
    NAME = "mesh_security"
    VERSION = "6.0.3"

    _peers: dict[str, dict] = {}
    _nonces_seen: dict[str, set] = {}
    _alerts: list[dict] = []
    _lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def track_peer(cls, peer_id: str, ip: str, introducer: str = ""):
        now = time.time()
        with cls._lock:
            if peer_id not in cls._peers:
                cls._peers[peer_id] = {
                    "first_seen": now, "last_seen": now,
                    "ips": set(), "introducers": set(),
                    "heartbeat_count": 0,
                }
            p = cls._peers[peer_id]
            p["last_seen"] = now
            p["heartbeat_count"] = p.get("heartbeat_count", 0) + 1
            p["ips"].add(ip)
            if introducer:
                p["introducers"].add(introducer)

    @classmethod
    def check_nonce(cls, peer_id: str, nonce: int) -> bool:
        with cls._lock:
            if peer_id not in cls._nonces_seen:
                cls._nonces_seen[peer_id] = set()
            if nonce in cls._nonces_seen[peer_id]:
                cls._alerts.append({
                    "time": time.time(),
                    "type": "replay_attack",
                    "peer": peer_id,
                    "nonce": nonce,
                })
                return False
            cls._nonces_seen[peer_id].add(nonce)
            if len(cls._nonces_seen[peer_id]) > 1000:
                cls._nonces_seen[peer_id] = set(list(cls._nonces_seen[peer_id])[-500:])
            return True

    @classmethod
    def scan_threats(cls) -> list[dict]:
        threats = []
        with cls._lock:
            now = time.time()
            ip_counts: dict[str, int] = {}
            ip_peers: dict[str, list[str]] = {}
            for pid, info in cls._peers.items():
                for ip in info.get("ips", set()):
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    if ip not in ip_peers:
                        ip_peers[ip] = []
                    ip_peers[ip].append(pid)

            for ip, count in ip_counts.items():
                if count > MESH_SYBIL_THRESHOLD:
                    threats.append({
                        "time": now,
                        "type": "sybil",
                        "ip": ip,
                        "peer_count": count,
                        "peers": ip_peers[ip],
                    })

            for pid, info in cls._peers.items():
                if len(info.get("introducers", set())) == 1:
                    single = list(info["introducers"])[0]
                    introduced_by = [p for p, i in cls._peers.items()
                                     if single in i.get("introducers", set())]
                    if len(introduced_by) > len(cls._peers) * MESH_ECLIPSE_THRESHOLD:
                        threats.append({
                            "time": now,
                            "type": "eclipse",
                            "victim": pid,
                            "dominator": single,
                            "controlled": len(introduced_by),
                            "total": len(cls._peers),
                        })

                uptime = now - info.get("first_seen", now)
                if uptime > MESH_DISAPPEAR_HOURS * 3600:
                    if now - info.get("last_seen", now) > 300:
                        threats.append({
                            "time": now,
                            "type": "disappeared",
                            "peer": pid,
                            "uptime_h": uptime / 3600,
                            "last_seen_s": now - info.get("last_seen", now),
                        })

        return threats

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        threats = cls.scan_threats()
        return {
            "enabled": MESH_ATTACK_DETECT,
            "known_peers": len(cls._peers),
            "active_threats": len(threats),
            "threats": threats[-10:] if threats else [],
            "alerts": cls._alerts[-10:] if cls._alerts else [],
        }

    @classmethod
    def get_graph(cls) -> dict:
        with cls._lock:
            return {
                "nodes": list(cls._peers.keys()),
                "edges": [
                    {"from": pid, "to": intro, "type": "introducer"}
                    for pid, info in cls._peers.items()
                    for intro in info.get("introducers", set())
                ],
            }
