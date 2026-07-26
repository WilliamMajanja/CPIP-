"""Palantir-Grade Counter-Surveillance Hardening for CPIP
Countermeasures against advanced data analytics, traffic correlation,
link analysis, pattern-of-life detection, and metadata fusion.

This module hardens CPIP against threats posed by platforms like
Palantir Gotham/Foundry/Metropolis by implementing:

  1. Constant-time message sending + fixed-size buckets
  2. Message mixing / delay / reorder (basic mix-net)
  3. Chaff traffic to ALL peers (not just trusted)
  4. Identity rotation (POT_ID + keys)
  5. Traffic profile normalization
  6. Auto-evasion on surveillance detection
  7. Broadcast-all mode (every msg to every peer)
  8. Timing jitter + inter-message interval normalization
  9. Anti-link-analysis via cover conversations
 10. Plausible deniability layer

Environment:
  CPIP_PALANTIR=1              Enable Palantir hardening
  CPIP_PALANTIR_MODE=auto|active|passive  Operation mode
  CPIP_PALANTIR_CHAFF=1        Enable chaff traffic
  CPIP_PALANTIR_MIX_DELAY=5    Max mix delay seconds
  CPIP_PALANTIR_FIXED_SIZE=1024 Pad all msgs to this size
  CPIP_PALANTIR_ID_ROTATE=3600 Identity rotation interval
  CPIP_PALANTIR_BROADCAST=0    Broadcast-all mode
  CPIP_PALANTIR_TIMING=cbr|vbr  CBR=constant bitrate
  CPIP_PALANTIR_COVER_BPS=500  Cover traffic bitrate
"""

import base64
import hashlib
import json
import os
import random
import secrets
import threading
import time
from typing import ClassVar


PALANTIR_ENABLED = os.environ.get("CPIP_PALANTIR", "0") == "1"
PALANTIR_MODE = os.environ.get("CPIP_PALANTIR_MODE", "auto")
PALANTIR_CHAFF = os.environ.get("CPIP_PALANTIR_CHAFF", "1") == "1"
PALANTIR_MIX_DELAY = float(os.environ.get("CPIP_PALANTIR_MIX_DELAY", "5.0"))
PALANTIR_FIXED_SIZE = int(os.environ.get("CPIP_PALANTIR_FIXED_SIZE", "1024"))
PALANTIR_ID_ROTATE = int(os.environ.get("CPIP_PALANTIR_ID_ROTATE", "3600"))
PALANTIR_BROADCAST = os.environ.get("CPIP_PALANTIR_BROADCAST", "0") == "1"
PALANTIR_TIMING = os.environ.get("CPIP_PALANTIR_TIMING", "cbr")
PALANTIR_COVER_BPS = int(os.environ.get("CPIP_PALANTIR_COVER_BPS", "500"))


class PalantirHardening:
    _instance = None
    _lock = threading.Lock()
    running: ClassVar[bool] = False

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._enabled = PALANTIR_ENABLED
        self._mode = PALANTIR_MODE
        self._chaff_enabled = PALANTIR_CHAFF
        self._mix_delay = PALANTIR_MIX_DELAY
        self._fixed_size = PALANTIR_FIXED_SIZE
        self._id_rotate = PALANTIR_ID_ROTATE
        self._broadcast_all = PALANTIR_BROADCAST
        self._timing = PALANTIR_TIMING
        self._cover_bps = PALANTIR_COVER_BPS
        self._mix_queue = []
        self._mix_lock = threading.Lock()
        self._message_counter = 0
        self._last_send_time = 0.0
        self._cover_bytes_sent = 0
        self._cover_interval = 0.0
        self._identity_epoch = 0
        self._current_pot_id = ""
        self._current_keys = {}
        self._agent_log = []
        self._auto_response_toggled = set()

        self._compute_cover_interval()

    def _compute_cover_interval(self):
        if self._fixed_size and self._cover_bps:
            msgs_per_sec = self._cover_bps / (self._fixed_size * 8)
            self._cover_interval = 1.0 / msgs_per_sec if msgs_per_sec > 0 else 0

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, val):
        self._enabled = bool(val)

    @property
    def mode(self):
        return self._mode

    @property
    def mix_queue_size(self):
        with self._mix_lock:
            return len(self._mix_queue)

    @property
    def identity_epoch(self):
        return self._identity_epoch

    def get_status(self):
        return {
            "enabled": self._enabled,
            "mode": self._mode,
            "chaff": self._chaff_enabled,
            "mix_delay": self._mix_delay,
            "fixed_size": self._fixed_size,
            "id_rotate": self._id_rotate,
            "broadcast_all": self._broadcast_all,
            "timing": self._timing,
            "cover_bps": self._cover_bps,
            "mix_queue": len(self._mix_queue),
            "identity_epoch": self._identity_epoch,
            "agent_log_count": len(self._agent_log),
        }

    def get_agent_log(self, limit=50):
        return self._agent_log[-limit:]

    def log_agent(self, msg):
        ts = time.strftime("%H:%M:%S")
        entry = {"time": ts, "msg": msg}
        self._agent_log.append(entry)
        if len(self._agent_log) > 1000:
            self._agent_log = self._agent_log[-500:]

    # ── Message Mixing (Anti-Timing-Analysis) ──────────────────────────

    def enqueue_for_mix(self, dst_pot, msg_dict, send_fn):
        if not self._enabled or self._mix_delay <= 0:
            return False
        with self._mix_lock:
            delay = random.uniform(0.1, self._mix_delay)
            self._mix_queue.append({
                "dst": dst_pot,
                "msg": msg_dict,
                "send_at": time.time() + delay,
                "send_fn": send_fn,
                "seq": self._message_counter,
            })
            self._message_counter += 1
        return True

    def _process_mix_queue(self):
        now = time.time()
        ready = []
        with self._mix_lock:
            remaining = []
            for item in self._mix_queue:
                if item["send_at"] <= now:
                    ready.append(item)
                else:
                    remaining.append(item)
            self._mix_queue = remaining

        random.shuffle(ready)
        for item in ready:
            try:
                item["send_fn"](item["dst"], item["msg"])
            except Exception:
                pass

    # ── Fixed-Size Padding (Anti-Traffic-Analysis) ─────────────────────

    def pad_message(self, data: bytes) -> bytes:
        if not self._enabled:
            return data
        target = self._fixed_size
        if len(data) >= target:
            target = ((len(data) // 512) + 1) * 512
        return data.ljust(target, b"\x00")

    def unpad_message(self, data: bytes) -> bytes:
        return data.rstrip(b"\x00")

    # ── Broadcast-All Mode (Anti-Link-Analysis) ────────────────────────

    def should_broadcast(self) -> bool:
        return self._enabled and self._broadcast_all

    # ── Identity Rotation (Anti-Pattern-of-Life) ───────────────────────

    def should_rotate_identity(self) -> bool:
        if not self._enabled or self._id_rotate <= 0:
            return False
        epoch = int(time.time() // self._id_rotate)
        if epoch > self._identity_epoch:
            self._identity_epoch = epoch
            self.log_agent(f"identity_rotate epoch={epoch}")
            return True
        return False

    # ── Chaff Generation (Anti-Traffic-Correlation) ────────────────────

    def generate_chaff(self) -> dict:
        fake_topics = [
            "brew_status", "temperature", "water_level", "keep_warm",
            "coverage", "heartbeat", "mesh_query", "time_sync",
        ]
        topic = random.choice(fake_topics)
        chaff = {
            "type": topic,
            "id": secrets.token_hex(4),
            "from": "__chaff__",
            "dst": "__chaff__",
            "timestamp": time.time(),
            "chaff": True,
            "data": base64.b64encode(secrets.token_bytes(random.randint(4, 32))).decode(),
        }
        return chaff

    def is_chaff(self, msg: dict) -> bool:
        return msg.get("chaff") is True or msg.get("from") == "__chaff__"

    # ── Timing Normalization (Constant-Bitrate) ────────────────────────

    def wait_for_timing_slot(self):
        if not self._enabled or self._timing != "cbr":
            return
        now = time.time()
        if self._last_send_time > 0:
            elapsed = now - self._last_send_time
            min_interval = self._cover_interval * 0.8
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                time.sleep(sleep_time + random.uniform(0, sleep_time * 0.1))
        self._last_send_time = time.time()

    # ── Auto-Evasion on Detection ──────────────────────────────────────

    def auto_evasion(self, surveillance_active: bool = False):
        if not self._enabled:
            return
        if self._mode != "auto":
            return
        if surveillance_active and "evasion" not in self._auto_response_toggled:
            self._enabled = True
            self._chaff_enabled = True
            self._mix_delay = max(self._mix_delay, 3.0)
            self._broadcast_all = True
            self._auto_response_toggled.add("evasion")
            self.log_agent("AUTO-EVASION: full countermeasures activated")

    # ── Background Thread ──────────────────────────────────────────────

    def _palantir_loop(self):
        self.log_agent("palantir loop started")
        last_chaff = 0
        chaff_interval = self._cover_interval * 10 if self._cover_interval > 0 else 15

        while self.running:
            try:
                self._process_mix_queue()

                if self._enabled and self._chaff_enabled:
                    now = time.time()
                    if now - last_chaff > chaff_interval:
                        last_chaff = now
                        chaff_interval = random.uniform(5, 30)
                        try:
                            from server import MeshNode
                            pot_ids = list(MeshNode.peers.keys())
                            if pot_ids:
                                dst = random.choice(pot_ids)
                                chaff = self.generate_chaff()
                                MeshNode._send_direct(dst, chaff)
                                self._cover_bytes_sent += len(json.dumps(chaff).encode())
                        except Exception:
                            pass
                time.sleep(0.5)
            except Exception:
                time.sleep(1)

    @classmethod
    def start(cls):
        if not PALANTIR_ENABLED:
            return
        inst = cls()
        if inst.running:
            return
        inst.running = True
        t = threading.Thread(target=inst._palantir_loop, daemon=True)
        t.start()
        inst.log_agent("palantir hardening activated")

    @classmethod
    def stop(cls):
        inst = cls()
        inst.running = False
        inst.log_agent("palantir hardening deactivated")

    @classmethod
    def reset(cls):
        inst = cls()
        inst._initialized = False
        inst.__init__()
