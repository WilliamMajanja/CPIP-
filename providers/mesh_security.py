from __future__ import annotations

import json
import ipaddress
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
    VERSION = "7.0.0"

    _peers: dict[str, dict] = {}
    _nonces_seen: dict[str, set] = {}
    _nonce_highwater: dict[str, int] = {}
    _alerts: list[dict] = []
    _lock = threading.Lock()
    _running = False
    _thread: threading.Thread | None = None

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._scan_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _scan_loop(cls):
        while cls._running:
            try:
                for t in cls.scan_threats():
                    cls._alerts.append({"time": time.time(), "detected": t})
                if len(cls._alerts) > 100:
                    cls._alerts = cls._alerts[-100:]
            except Exception as e:
                logger.debug("Mesh security scan error: %s", e)
            time.sleep(60)

    @classmethod
    def _subnet24(cls, ip: str) -> str:
        try:
            address = ipaddress.ip_address(ip)
            prefix = 24 if address.version == 4 else 64
            return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
        except ValueError:
            return "unknown"

    @classmethod
    def track_peer(cls, peer_id: str, ip: str, introducer: str = ""):
        if not MESH_ATTACK_DETECT:
            return
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
        if not MESH_ATTACK_DETECT:
            return True
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
            highest = cls._nonce_highwater.get(peer_id)
            if highest is not None and nonce <= highest:
                cls._alerts.append({"time": time.time(), "type": "out_of_order_nonce",
                                    "peer": peer_id, "nonce": nonce, "highest": highest})
                return False
            cls._nonces_seen[peer_id].add(nonce)
            cls._nonce_highwater[peer_id] = nonce
            if len(cls._nonces_seen[peer_id]) > 1000:
                cls._nonces_seen[peer_id] = {highest}
            return True

    @classmethod
    def scan_threats(cls) -> list[dict]:
        if not MESH_ATTACK_DETECT:
            return []
        threats = []
        with cls._lock:
            now = time.time()
            subnet_counts: dict[str, int] = {}
            subnet_peers: dict[str, list[str]] = {}
            for pid, info in cls._peers.items():
                for ip in info.get("ips", set()):
                    subnet = cls._subnet24(ip)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    subnet_peers.setdefault(subnet, []).append(pid)

            for subnet, count in subnet_counts.items():
                if count > MESH_SYBIL_THRESHOLD:
                    threats.append({
                        "time": now,
                        "type": "sybil",
                        "subnet": subnet,
                        "peer_count": count,
                        "peers": subnet_peers[subnet],
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
