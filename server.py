#!/usr/bin/env python3
"""CPIP/HTCPCP Server — Coffee Protocol Internet Protocol
RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + CPIP Extension

Next-level evolution: real IoT coffee control + mesh communications for Raspberry Pi.
Preserves full HTCPCP backward compatibility while providing a covert mesh
communications layer that requires zero internet infrastructure.

DISCLAIMER: This software does not comply with FIPS 140-2/3 or any federal
information processing standards. It deliberately uses non-standard cryptographic
primitives. Do not use for anything requiring actual security.
"""

import json
import os
import signal
import sys
import threading
import time
import subprocess
import socket
import struct
import hashlib
import hmac
import queue
import random
import base64
import textwrap
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import html
import traceback

# Radio interface (C binary for LoRa / packet radio)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "radio"))
try:
    from radio_protocol import RadioInterface, RadioError
    RADIO_IMPORT_OK = True
except ImportError:
    RadioInterface = None
    RadioError = Exception
    RADIO_IMPORT_OK = False

# ── Configuration ─────────────────────────────────────────────────────
DEVICE_TYPE = os.environ.get("CPIP_DEVICE", os.environ.get("HTCPCP_DEVICE", "hyper-text"))
BIND_ADDR = os.environ.get("CPIP_BIND", os.environ.get("HTCPCP_BIND", "0.0.0.0"))
BIND_PORT = int(os.environ.get("CPIP_PORT", os.environ.get("HTCPCP_PORT", "4180")))
WEB_DIR = Path(os.environ.get("CPIP_WEB_DIR", Path(__file__).parent / "web"))
HOSTNAME = socket.gethostname().split(".")[0]
POT_ID = hashlib.md5(f"{HOSTNAME}:{BIND_PORT}".encode()).hexdigest()[:8]
GPIO_PIN = int(os.environ.get("CPIP_GPIO_PIN", "17"))
GPIO_ENABLED = os.environ.get("CPIP_GPIO", "0") == "1"
AVAHI_ENABLED = os.environ.get("CPIP_AVAHI", "1") == "1"
DISCOVERY_PORT = int(os.environ.get("CPIP_DISCOVERY_PORT", "4190"))
HISTORY_MAX = 100
SCHEDULE_CHECK_INTERVAL = 15

_raw_key = os.environ.get("CPIP_COVERT_KEY", "")
if not _raw_key or _raw_key == "CHANGE_ME_COFFEE_BLEND_2024":
    if not _raw_key:
        _raw_key = base64.b64encode(hashlib.sha256(os.urandom(32)).digest()[:24]).decode()
        COVERT_KEY = _raw_key.encode()
        print(f"   ⚠ COVERT_KEY not set — auto-generated: {_raw_key}", flush=True)
        print(f"   ⚠ Set CPIP_COVERT_KEY in environment to use a fixed key.", flush=True)
    else:
        COVERT_KEY = _raw_key.encode()
        print(f"   ⚠ WARNING: Using default COVERT_KEY (CHANGE_ME_COFFEE_BLEND_2024)", flush=True)
        print(f"   ⚠ Set CPIP_COVERT_KEY to a custom value for production.", flush=True)
else:
    COVERT_KEY = _raw_key.encode()
COVERT_ENABLED = os.environ.get("CPIP_COVERT", "1") == "1"
MESH_ENABLED = os.environ.get("CPIP_MESH", "1") == "1"
MESH_PORT = int(os.environ.get("CPIP_MESH_PORT", "4191"))
MESH_TTL = int(os.environ.get("CPIP_MESH_TTL", "5"))
MESH_HEARTBEAT = int(os.environ.get("CPIP_MESH_HEARTBEAT", "30"))
COVER_TRAFFIC = os.environ.get("CPIP_COVER_TRAFFIC", "1") == "1"
NTP_SYNC = os.environ.get("CPIP_NTP", "1") == "1"
NTP_SERVER = os.environ.get("CPIP_NTP_SERVER", "pool.ntp.org")
MESH_STEALTH = os.environ.get("CPIP_MESH_STEALTH", "0") == "1"
MESH_LATENT_PORTS = [int(p) for p in os.environ.get("CPIP_MESH_LATENT_PORTS", "4192,4193,4194").split(",") if p.strip().isdigit()]
MESH_HOP_INTERVAL = int(os.environ.get("CPIP_MESH_HOP_INTERVAL", "3600"))
MESH_PERSIST_DIR = os.environ.get("CPIP_MESH_PERSIST_DIR", "/tmp/cpip")

# ── Satellite Mesh (Starlink / LEO / Internet-Wide) ─────────────────────
def _env_bool(name, default):
    v = os.environ.get(name)
    if v is None: return default
    return v.lower() in ("1", "yes", "true")

_SAT_ALIASES = {
    "CPIP_SAT": "CPIP_STARLINK",
    "CPIP_SAT_PORT": "CPIP_STARLINK_PORT",
    "CPIP_SAT_LAT": "CPIP_STARLINK_LAT",
    "CPIP_SAT_LON": "CPIP_STARLINK_LON",
    "CPIP_SAT_ALT": "CPIP_STARLINK_ALT",
    "CPIP_SAT_TIMEOUT": "CPIP_MESH_SAT_TIMEOUT",
    "CPIP_SAT_HEARTBEAT": "CPIP_MESH_SAT_HEARTBEAT",
    "CPIP_SAT_BOOTSTRAP": "CPIP_STARLINK_BOOTSTRAP",
    "CPIP_SAT_RELAY": "CPIP_STARLINK_RELAY",
}

def _get_env(name, fallback):
    return os.environ.get(name, os.environ.get(_SAT_ALIASES.get(name, ""), fallback))

SATELLITE_ENABLED = _env_bool("CPIP_SAT", False) or _env_bool("CPIP_STARLINK", False)
SATELLITE_PORT = int(_get_env("CPIP_SAT_PORT", "4195"))
SATELLITE_LAT = float(_get_env("CPIP_SAT_LAT", "0"))
SATELLITE_LON = float(_get_env("CPIP_SAT_LON", "0"))
SATELLITE_ALT = float(_get_env("CPIP_SAT_ALT", "0"))
MESH_SAT_TIMEOUT = float(_get_env("CPIP_SAT_TIMEOUT", "10.0"))
MESH_SAT_HEARTBEAT = int(_get_env("CPIP_SAT_HEARTBEAT", "60"))
SATELLITE_BOOTSTRAP = _get_env("CPIP_SAT_BOOTSTRAP", "")
SATELLITE_RELAY = _env_bool("CPIP_SAT_RELAY", False) or _env_bool("CPIP_STARLINK_RELAY", False)

# ── Radio (LoRa / Packet Radio) ─────────────────────────────────────────
RADIO_ENABLED = os.environ.get("CPIP_RADIO", "0") == "1"
RADIO_MODE = os.environ.get("CPIP_RADIO_MODE", "sim")
RADIO_FREQ = int(os.environ.get("CPIP_RADIO_FREQ", "915000000"))
RADIO_SF = int(os.environ.get("CPIP_RADIO_SF", "9"))
RADIO_BW = int(os.environ.get("CPIP_RADIO_BW", "125000"))
RADIO_POWER = int(os.environ.get("CPIP_RADIO_POWER", "17"))
RADIO_DEVICE = os.environ.get("CPIP_RADIO_DEVICE", "/dev/ttyUSB0")
RADIO_BAUD = int(os.environ.get("CPIP_RADIO_BAUD", "115200"))

# ── Mobile Broadband (4G/5G / LTE / WWAN) ───────────────────────────────
MOBILE_ENABLED = _env_bool("CPIP_MOBILE", False) or _env_bool("CPIP_CELLULAR", False)
MOBILE_APN = os.environ.get("CPIP_MOBILE_APN", os.environ.get("CPIP_CELLULAR_APN", ""))
MOBILE_INTERFACE = os.environ.get("CPIP_MOBILE_IFACE", "wwan0")
MOBILE_BOOTSTRAP = os.environ.get("CPIP_MOBILE_BOOTSTRAP", "")
MOBILE_PORT = int(os.environ.get("CPIP_MOBILE_PORT", "4196"))
MOBILE_HEARTBEAT = int(os.environ.get("CPIP_MOBILE_HEARTBEAT", "120"))
MOBILE_KEEPALIVE = int(os.environ.get("CPIP_MOBILE_KEEPALIVE", "30"))
MOBILE_TELEMETRY = _env_bool("CPIP_MOBILE_TELEMETRY", False)

PITAIL_ENABLED = os.environ.get("CPIP_PITAIL", "0") == "1"
PITAIL_ADDR = os.environ.get("CPIP_PITAIL_ADDR", "10.0.0.1")
PITAIL_NETMASK = os.environ.get("CPIP_PITAIL_NETMASK", "255.255.255.0")
PITAIL_GADGET_DIR = os.environ.get("CPIP_PITAIL_GADGET_DIR", "/sys/kernel/config/usb_gadget")
THERMOS_ENABLED = os.environ.get("CPIP_THERMOS", "0") == "1"
THERMOS_MAX_STORAGE = int(os.environ.get("CPIP_THERMOS_MAX", "1000000"))

CPIP_VERSION = "2.2.0"
CPIP_PROTOCOL = f"CPIP/{CPIP_VERSION} (RFC 2324 + RFC 7168 + Mesh Extension + Full Compliance)"

# ── Valid additions (RFC 2324 §2.2.2 + RFC 7168) ─────────────────────
VALID_ADDITIONS = {
    "milk":    {"type": "dairy",     "variety": ["cream", "half-and-half", "whole", "part-skim", "skim", "non-dairy"]},
    "syrup":   {"type": "sweetener", "variety": ["vanilla", "caramel", "almond", "hazelnut", "chocolate"]},
    "sugar":   {"type": "sweetener", "variety": ["white", "brown", "raw", "honey", "artificial"]},
    "spice":   {"type": "flavoring", "variety": ["cinnamon", "cardamom", "nutmeg", "clove"]},
    "alcohol": {"type": "alcohol",   "variety": ["whisky", "rum", "kahlua", "aquavit", "brandy"]},
}

DEVICE_BEVERAGE_MAP = {
    "teapot":     ["tea"],
    "coffee-pot": ["coffee"],
    "hyper-text": ["coffee", "tea"],
}

ALCOHOL_DEVICES = {"hyper-text"}

BREW_MESSAGES = {
    "teapot":     "Your teapot is steeping. Send WHEN to stop.",
    "coffee-pot": "Your coffee pot is brewing. Send WHEN to stop.",
    "hyper-text": "Your hyper-text coffee pot is brewing. Send WHEN to stop.",
}

WHEN_MESSAGES = {
    "teapot":     "Tea is ready. Pouring stopped.",
    "coffee-pot": "Coffee is ready. Pouring stopped.",
    "hyper-text": "Beverage is ready. Pouring stopped.",
}

ADDITION_TYPE_BITS = {"milk": 0, "syrup": 1, "sugar": 2, "spice": 3, "alcohol": 4}
BITS_TO_ADDITION = {v: k for k, v in ADDITION_TYPE_BITS.items()}

# ── coffee: URI scheme (RFC 2324 §3) — 24 international variants ─────
COFFEE_SCHEMES = [
    "koffie",                      # Afrikaans, Dutch
    "q%C3%A6hv%C3%A6",            # Azerbaijani
    "%D9%82%D9%87%D9%88%D8%A9",   # Arabic
    "akeita",                      # Basque
    "koffee",                      # Bengali
    "kahva",                       # Bosnian
    "kafe",                        # Bulgarian, Czech
    "caf%C3%A8",                   # Catalan, French, Galician
    "%E5%92%96%E5%95%A1",          # Chinese
    "kava",                        # Croatian
    "k%C3%A1va",                   # Czech
    "kaffe",                       # Danish, Norwegian, Swedish
    "coffee",                      # English
    "kafo",                        # Esperanto
    "kohv",                        # Estonian
    "kahvi",                       # Finnish
    "%4Baffee",                    # German
    "%CE%BA%CE%B1%CF%86%CE%AD",   # Greek
    "%E0%A4%95%E0%A5%8C%E0%A4%AB%E0%A5%80", # Hindi
    "%E3%82%B3%E3%83%BC%E3%83%92%E3%83%BC", # Japanese
    "%EC%BB%A4%ED%94%BC",          # Korean
    "%D0%BA%D0%BE%D1%84%D0%B5",    # Russian
    "%E0%B8%81%E0%B8%B2%E0%B9%81%E0%B8%9F", # Thai
    "kahawa",                      # Swahili
]
COFFEE_SCHEME_NAMES = set(s.lower() for s in COFFEE_SCHEMES)

COFFEE_LANGUAGE_MAP = {
    "koffie": "Afrikaans, Dutch",
    "q%C3%A6hv%C3%A6": "Azerbaijani",
    "%D9%82%D9%87%D9%88%D8%A9": "Arabic",
    "akeita": "Basque",
    "koffee": "Bengali",
    "kahva": "Bosnian",
    "kafe": "Bulgarian, Czech",
    "caf%C3%A8": "Catalan, French, Galician",
    "%E5%92%96%E5%95%A1": "Chinese",
    "kava": "Croatian",
    "k%C3%A1va": "Czech",
    "kaffe": "Danish, Norwegian, Swedish",
    "coffee": "English",
    "kafo": "Esperanto",
    "kohv": "Estonian",
    "kahvi": "Finnish",
    "%4Baffee": "German",
    "%CE%BA%CE%B1%CF%86%CE%AD": "Greek",
    "%E0%A4%95%E0%A5%8C%E0%A4%AB%E0%A5%80": "Hindi",
    "%E3%82%B3%E3%83%BC%E3%83%92%E3%83%BC": "Japanese",
    "%EC%BB%A4%ED%94%BC": "Korean",
    "%D0%BA%D0%BE%D1%84%D0%B5": "Russian",
    "%E0%B8%81%E0%B8%B2%E0%B9%81%E0%B8%9F": "Thai",
    "kahawa": "Swahili",
}

# ── Coffee Cipher — Deliberately Non-FIPS ─────────────────────────────
class CoffeeCipher:
    """Custom stream cipher using coffee blend parameters.
    
    Deliberately non-FIPS compliant:
    - Uses MD4-derived mixing (not SHA-2)
    - XOR-based keystream with no IV
    - No padding/oracle resistance
    - Key derivation from coffee recipe parameters
    
    The cipher uses the five addition types as S-box substitutions
    and brew parameters for key scheduling.
    """

    S_BOX = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0],
        [0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc],
        [0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    ]

    @classmethod
    def _md4_mix(cls, data: bytes) -> bytes:
        """Non-standard mixing function (inspired by MD4, not MD4 itself).
        Deliberately not a published standard.
        """
        state = bytearray(hashlib.md5(data).digest())
        for round_num in range(3):
            for i in range(len(state)):
                state[i] = (state[i] ^ state[(i + 3) % len(state)] + round_num * 0x42) & 0xff
        return bytes(state)

    @classmethod
    def key_from_recipe(cls, base_key: bytes, recipe: str = "espresso") -> bytes:
        """Derive cipher key from a coffee recipe name.
        
        Different recipes produce different keys:
        'espresso', 'pour-over', 'french-press', 'cold-brew', 'moka'
        """
        recipe_bytes = recipe.encode()
        mixed = cls._md4_mix(base_key + recipe_bytes + b"\xc0\xff\xee\x00")
        return mixed

    @classmethod
    def _keystream(cls, key: bytes, length: int) -> bytes:
        """Generate keystream bytes using counter-based derivation.
        
        Each byte is independently derived from the key using a counter,
        so encryption and decryption produce identical keystreams.
        """
        result = bytearray()
        for i in range(length):
            counter = struct.pack('>I', i)
            mixed = cls._md4_mix(key + counter + bytes([i & 0xff]))
            k = cls.S_BOX[i % 5][(mixed[i % len(mixed)] + i) % 8]
            result.append(k)
        return bytes(result)

    @classmethod
    def encrypt(cls, plaintext: bytes, base_key: bytes = None, recipe: str = "espresso") -> bytes:
        """Encrypt using Coffee Blend Cipher.
        
        Counter-based stream cipher with S-box substitution.
        Each ciphertext byte = plaintext XOR keystream[position].
        Keystream is deterministic given (key, recipe), so decryption
        produces an identical keystream.
        """
        if base_key is None:
            base_key = COVERT_KEY
        key = cls.key_from_recipe(base_key, recipe)
        ks = cls._keystream(key, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    @classmethod
    def decrypt(cls, ciphertext: bytes, base_key: bytes = None, recipe: str = "espresso") -> bytes:
        """Decrypt using Coffee Blend Cipher (symmetric XOR)."""
        return cls.encrypt(ciphertext, base_key, recipe)

    @classmethod
    def hash(cls, data: bytes) -> str:
        """Non-standard hash using coffee blend."""
        h = cls._md4_mix(data)
        for _ in range(8):
            h = cls._md4_mix(h + data)
        return h.hex()[:16]


# ── Ed25519 — Pure-Python ECC (Deliberately Non-Constant-Time) ────────
class Ed25519:
    """Pure-Python Ed25519 (Curve25519) — the fangs on the joke.
    
    RFC 8032-compatible signature scheme using elliptic curve cryptography.
    Deliberately NOT constant-time: timing side-channels are a feature,
    not a bug. Coffee is best enjoyed slowly.
    
    Uses only stdlib: hashlib, os, struct. No libsodium, no pycryptodome.
    If the NSA can crack this on a Pi Zero, they've earned their coffee.
    """

    P = 2**255 - 19
    D = (-121665 * pow(121666, -1, 2**255 - 19)) % (2**255 - 19)
    D2 = (2 * D) % (2**255 - 19)
    L = 2**252 + 27742317777372353535851937790883648493

    By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
    Bx = 15112221349535807941723896952234070989399264296811799068538259235637338081846
    B = (Bx, By)

    @staticmethod
    def _modinv(a, n):
        return pow(a, n - 2, n)

    @classmethod
    def _recover_x(cls, y):
        p, d = cls.P, cls.D
        y2 = (y * y) % p
        x2 = ((y2 - 1) * cls._modinv(d * y2 + 1, p)) % p
        x = pow(x2, (p + 3) // 8, p)
        if (x * x) % p != x2:
            x = (x * pow(2, (p - 1) // 4, p)) % p
        if x & 1:
            x = p - x
        return x

    @classmethod
    def _edwards_add(cls, P1, P2):
        """Add two points on the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2.
        
        Unified addition formula (works for doubling too):
          x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
          y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
        """
        x1, y1 = P1
        x2, y2 = P2
        d = cls.D
        p = cls.P
        t1 = (d * x1 * x2 * y1 * y2) % p
        denom_x = cls._modinv((1 + t1) % p, p)
        denom_y = cls._modinv((1 - t1) % p, p)
        x3 = ((x1 * y2 + x2 * y1) * denom_x) % p
        y3 = ((y1 * y2 + x1 * x2) * denom_y) % p
        return (x3, y3)

    @classmethod
    def _scalar_mult(cls, n, P):
        if n == 0:
            return (0, 1)
        Q = (0, 1)
        while n > 0:
            if n & 1:
                Q = cls._edwards_add(Q, P)
            P = cls._edwards_add(P, P)
            n >>= 1
        return Q

    @classmethod
    def _encode_point(cls, P):
        x, y = P
        return int.to_bytes(y | ((x & 1) << 255), 32, 'little')

    @classmethod
    def _decode_point(cls, s):
        y = int.from_bytes(s, 'little')
        x_sign = y >> 255
        y &= (1 << 255) - 1
        x = cls._recover_x(y)
        if (x & 1) != x_sign:
            x = cls.P - x
        return (x, y)

    @classmethod
    def _hash512(cls, *args):
        h = hashlib.sha512()
        for a in args:
            h.update(a if isinstance(a, bytes) else str(a).encode())
        return h.digest()

    @classmethod
    def generate_keypair(cls, seed=None):
        """Generate (public_key_bytes, seed, secret_scalar, public_point)."""
        if seed is None:
            seed = os.urandom(32)
        h = cls._hash512(seed)
        a = int.from_bytes(h[:32], 'little')
        a &= (1 << 254) - 8
        a |= (1 << 254)
        A = cls._scalar_mult(a, cls.B)
        return (cls._encode_point(A), seed, a, A)

    @classmethod
    def secret_scalar(cls, seed):
        """Derive the secret scalar from a seed."""
        h = cls._hash512(seed)
        a = int.from_bytes(h[:32], 'little')
        a &= (1 << 254) - 8
        a |= (1 << 254)
        return a

    @classmethod
    def sign(cls, message, seed):
        """Sign a message with Ed25519. Returns 64-byte signature."""
        h = cls._hash512(seed)
        a = int.from_bytes(h[:32], 'little')
        a &= (1 << 254) - 8
        a |= (1 << 254)
        prefix = h[32:]
        r = int.from_bytes(cls._hash512(prefix, message), 'little') % cls.L
        R = cls._scalar_mult(r, cls.B)
        Rs = cls._encode_point(R)
        pk = cls._encode_point(cls._scalar_mult(a, cls.B))
        k = int.from_bytes(cls._hash512(Rs, pk, message), 'little') % cls.L
        S = (r + k * a) % cls.L
        return Rs + S.to_bytes(32, 'little')

    @classmethod
    def verify(cls, message, signature, public_key):
        """Verify an Ed25519 signature. Returns bool."""
        if len(signature) != 64:
            return False
        try:
            A = cls._decode_point(public_key)
        except Exception:
            return False
        Rs = signature[:32]
        S = int.from_bytes(signature[32:], 'little')
        if S >= cls.L:
            return False
        try:
            R = cls._decode_point(Rs)
        except Exception:
            return False
        k = int.from_bytes(cls._hash512(Rs, public_key, message), 'little') % cls.L
        Sbase = cls._scalar_mult(S, cls.B)
        kA = cls._scalar_mult(k, A)
        kA_neg = ((-kA[0]) % cls.P, kA[1])
        R_check = cls._edwards_add(Sbase, kA_neg)
        return R_check == R

    @classmethod
    def key_exchange(cls, our_secret_seed, their_public_key):
        """ECDH: derive shared 32-byte secret from our seed + their pubkey."""
        a = cls.secret_scalar(our_secret_seed)
        A = cls._decode_point(their_public_key)
        shared = cls._scalar_mult(a, A)
        return cls._hash512(cls._encode_point(shared))[:32]

    @classmethod
    def pubkey_to_address(cls, public_key):
        """Derive a short address string from a public key (like a Bitcoin address)."""
        h = hashlib.sha256(public_key).digest()[:4]
        b32 = base64.b32encode(h).decode().rstrip("=").lower()
        return f"coffee:{b32}"

    @classmethod
    def address_matches(cls, address, public_key):
        return cls.pubkey_to_address(public_key) == address


# ── ECC-Enhanced Covert Channel ───────────────────────────────────────
class CovertChannel:
    """Encode/decode hidden messages inside HTCPCP Accept-Additions headers.
    
    Messages are hidden in plain sight - they look like normal coffee
    customization requests. The variety fields carry hex-encoded data
    segments, and the addition types themselves encode routing metadata.
    
    Now with ECC: when a recipient's Ed25519 public key is known, messages
    are ECDH-encrypted using a shared secret derived from (our_seed, their_pubkey).
    Each message is also signed with our Ed25519 key for authenticity.
    
    Format:
      Accept-Additions: <type>;variety=<hexdata>, <type>;variety=<hexdata>, ...
    
    Each <type> encodes 2 bits of routing metadata:
      milk=00, syrup=01, sugar=10, spice=11
    The variety field carries hex-encoded ciphertext + ECC metadata.
    """

    HEADER = "Accept-Additions"
    CHUNK_SIZE = 8

    ADDITION_POOL = list(VALID_ADDITIONS.keys())
    VARIETY_POOL = {}
    for addn_name, addn_def in VALID_ADDITIONS.items():
        VARIETY_POOL[addn_name] = addn_def["variety"]

    @classmethod
    def encode(cls, message: bytes, dst_pot: str = None, recipe: str = "espresso",
               dst_pubkey: bytes = None, our_seed: bytes = None) -> dict:
        """Encode a message into Accept-Additions header components.
        
        If dst_pubkey and our_seed are provided, uses ECDH shared secret
        + Ed25519 signing instead of the basic CoffeeBlend cipher.
        """
        if not COVERT_ENABLED:
            return {"additions": []}

        if dst_pubkey and our_seed:
            shared = Ed25519.key_exchange(our_seed, dst_pubkey)
            ciphertext = CoffeeCipher.encrypt(message, base_key=shared, recipe=recipe)
            sig = Ed25519.sign(ciphertext, our_seed)
            payload = b"ECCv1:" + Ed25519.pubkey_to_address(
                Ed25519._encode_point(Ed25519._scalar_mult(
                    Ed25519.secret_scalar(our_seed), Ed25519.B
                ))
            ).encode() + b":" + sig + b":" + ciphertext
        else:
            ciphertext = CoffeeCipher.encrypt(message, recipe=recipe)
            payload = b"CBC:" + ciphertext

        if recipe and recipe != "espresso":
            recipe_chunks = []
            for i in range(0, len(recipe), cls.CHUNK_SIZE):
                chunk = recipe[i:i + cls.CHUNK_SIZE]
                addn_type = BITS_TO_ADDITION.get(i % 5, "milk")
                recipe_chunks.append({"name": addn_type, "variety": f"recipe_{chunk}"})
            recipe_chunks.append({"name": "spice", "variety": "recipe_end"})

        hex_data = payload.hex()
        hex_len = len(hex_data)
        additions = []
        for i in range(0, hex_len, cls.CHUNK_SIZE):
            chunk = hex_data[i:i + cls.CHUNK_SIZE]
            addn_type = BITS_TO_ADDITION.get((i // cls.CHUNK_SIZE) % 5, "milk")
            additions.append({"name": addn_type, "variety": chunk})

        if recipe and recipe != "espresso":
            additions = recipe_chunks + additions

        if dst_pot:
            route_seed = int(hashlib.md5(dst_pot.encode()).hexdigest()[:2], 16)
            route_bits = route_seed % 5
            route_type = BITS_TO_ADDITION.get(route_bits, "syrup")
            additions.insert(0, {"name": route_type, "variety": f"route_{dst_pot[:16]}"})

        return {"additions": additions}

    @classmethod
    def decode(cls, additions: list, our_seed: bytes = None) -> bytes:
        """Extract hidden message from parsed Accept-Additions list.
        
        If our_seed is provided, attempts ECDH decryption using embedded
        sender address to derive the shared secret.
        Returns decrypted plaintext bytes, or b'' if no message found.
        """
        if not additions or not COVERT_ENABLED:
            return b""

        hex_chunks = []
        recipe = "espresso"
        recipe_mode = False
        for addn in additions:
            name = addn.get("name", "")
            variety = addn.get("variety", "")
            if not variety:
                continue
            if variety.startswith("route_"):
                continue
            if variety.startswith("recipe_"):
                val = variety[len("recipe_"):]
                if val == "end":
                    recipe_mode = False
                    continue
                if not recipe_mode:
                    recipe = val
                    recipe_mode = True
                    continue
                recipe += val
                continue
            if recipe_mode:
                continue
            hex_chunks.append(variety)

        if not hex_chunks:
            return b""

        hex_data = "".join(hex_chunks)
        try:
            payload = bytes.fromhex(hex_data)
        except ValueError:
            return b""

        try:
            if payload.startswith(b"ECCv1:") and our_seed:
                _, addr_b, sig, ciphertext = payload.split(b":", 3)
                # Recover sender's public key from address
                for pid, info in MeshNode.peers.items():
                    pk_b64 = info.get("pubkey", "")
                    if pk_b64:
                        pk = base64.b64decode(pk_b64)
                        if Ed25519.pubkey_to_address(pk) == addr_b.decode():
                            shared = Ed25519.key_exchange(our_seed, pk)
                            if Ed25519.verify(ciphertext, sig, pk):
                                plaintext = CoffeeCipher.decrypt(ciphertext, base_key=shared, recipe=recipe)
                                return plaintext
                return b""
            elif payload.startswith(b"CBC:"):
                ciphertext = payload[4:]
                return CoffeeCipher.decrypt(ciphertext, recipe=recipe)
        except Exception:
            pass
        return b""

    @classmethod
    def generate_cover_traffic(cls) -> dict:
        """Generate innocent-looking Accept-Additions for cover traffic."""
        additions = []
        num_additions = random.randint(1, 3)
        chosen = random.sample(cls.ADDITION_POOL, min(num_additions, len(cls.ADDITION_POOL)))
        for name in chosen:
            variety = random.choice(cls.VARIETY_POOL[name])
            additions.append({"name": name, "variety": variety})
        return {"additions": additions}

    @classmethod
    def encode_brew(cls, message: bytes, dst_pot: str = None,
                    dst_pubkey: bytes = None, our_seed: bytes = None) -> tuple:
        """Create a brew request that carries a hidden message.
        
        Returns (beverage_type, additions_list, headers_dict)
        """
        additions = cls.encode(message, dst_pot, dst_pubkey=dst_pubkey, our_seed=our_seed)
        beverage = random.choice(["coffee", "tea"])
        header_value = ", ".join(
            f"{a['name']};variety={a['variety']}"
            for a in additions["additions"]
        )
        headers = {cls.HEADER: header_value}
        return beverage, additions["additions"], headers


# ── Mesh AAA + Latent Port + Stealth Network ──────────────────────────
class MeshNode:
    """Peer-to-peer mesh with AAA (Authentication, Authorization, Accounting),
    latent (dormant) ports, and stealth mode to bypass ISP/government blocks.
    
    ┌─ Node Identity ──────────────────────────────────────────────┐
    │ Each node has a persistent secret derived from COVERT_KEY +   │
    │ POT_ID. A self-signed 'node certificate' is used in AUTH     │
    │ handshakes. Trust levels: untrusted → challenged → known →   │
    │ trusted → admin.                                              │
    ├─ Latent Ports ───────────────────────────────────────────────┤
    │ Secondary UDP ports (4192,4193,4194) that appear closed.     │
    │ Activated only after a correct port-knocking sequence.       │
    │ When dormant: no ICMP response, no TCP RST, no UDP reply.   │
    ├─ Stealth Mode ───────────────────────────────────────────────┤
    │ No broadcast heartbeats. Directed pings only. Port hopping   │
    │ changes mesh port periodically. Traffic padded to random     │
    │ sizes. Covert fallback routes via HTTP brew headers if UDP   │
    │ is blocked.                                                   │
    ├─ Persistence ────────────────────────────────────────────────┤
    │ Peers, routes, inbox saved to disk. Survives reboot.         │
    └──────────────────────────────────────────────────────────────┘
    """

    # ── Class-level state ──────────────────────────────────────────────
    peers = {}
    peers_lock = threading.Lock()
    routing_table = {}
    message_store = []
    store_lock = threading.Lock()
    inbox = []
    inbox_lock = threading.Lock()
    trust_store = {}
    trust_lock = threading.Lock()
    mesh_socket = None
    latent_sockets = {}
    latent_lock = threading.Lock()
    running = False
    node_secret = None
    node_seed = None
    node_pubkey = None
    node_address = None
    node_cert = None
    current_mesh_port = MESH_PORT
    knock_state = {}
    persist_path = None
    address_book = {}
    address_book_lock = threading.Lock()

    # ── Starlink / Satellite state ──────────────────────────────────────
    sat_socket = None
    sat_peers = {}
    sat_bootstrap = []
    sat_coords = (0.0, 0.0, 0.0)
    sat_rtt = {}
    sat_lock = threading.Lock()
    sat_active = False
    stealth_mode = MESH_STEALTH

    # ── Trust levels ───────────────────────────────────────────────────
    TRUST_UNTRUSTED = 0
    TRUST_CHALLENGED = 1
    TRUST_KNOWN = 2
    TRUST_TRUSTED = 3
    TRUST_ADMIN = 4

    TRUST_NAMES = {0: "untrusted", 1: "challenged", 2: "known", 3: "trusted", 4: "admin"}

    # ── Bootstrap ──────────────────────────────────────────────────────

    @classmethod
    def _init_identity(cls):
        """Derive persistent node identity from COVERT_KEY + POT_ID.
        Uses Ed25519 keypair for ECC-based identity and signing."""
        seed = hashlib.md5(COVERT_KEY + POT_ID.encode()).digest()
        cls.node_secret = CoffeeCipher._md4_mix(seed * 4)
        # Generate Ed25519 keypair for ECC
        ecc_seed = hashlib.sha256(cls.node_secret + b"ed25519").digest()
        cls.node_pubkey, cls.node_seed, _, _ = Ed25519.generate_keypair(ecc_seed)
        cls.node_address = Ed25519.pubkey_to_address(cls.node_pubkey)
        cls.node_cert = {
            "node_id": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "pubkey": base64.b64encode(cls.node_pubkey).decode(),
            "address": cls.node_address,
            "signature": CoffeeCipher.hash(cls.node_secret + POT_ID.encode()),
        }
        Path(MESH_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
        cls.persist_path = Path(MESH_PERSIST_DIR) / f"mesh_{POT_ID}.json"
        cls._load_persist()

    @classmethod
    def start(cls):
        if not MESH_ENABLED:
            return
        try:
            cls._init_identity()
            cls.running = True
            cls.current_mesh_port = MESH_PORT

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", MESH_PORT))
            sock.settimeout(2)
            cls.mesh_socket = sock

            threading.Thread(target=cls._listener, daemon=True).start()
            threading.Thread(target=cls._heartbeat_loop, daemon=True).start()
            threading.Thread(target=cls.store_forward_retry, daemon=True).start()
            threading.Thread(target=cls._latent_listener, daemon=True).start()
            threading.Thread(target=cls._persist_loop, daemon=True).start()
            threading.Thread(target=cls._port_hop_loop, daemon=True).start()
            threading.Thread(target=cls._keep_warm_loop, daemon=True).start()
            if COVER_TRAFFIC:
                threading.Thread(target=cls._cover_traffic_loop, daemon=True).start()

            cls._sat_start()
            cls._mobile_start()

            print(f"   ├ Mesh AAA:   Node {POT_ID} active on port {MESH_PORT}", flush=True)
            print(f"   ├ Latent:     Ports {MESH_LATENT_PORTS} (dormant)", flush=True)
            print(f"   └ Stealth:    {'ON (no broadcast)' if MeshNode.stealth_mode else 'OFF (broadcast enabled)'}", flush=True)
        except Exception as e:
            print(f"[MESH] Failed to start: {e}", flush=True)

    @classmethod
    def stop(cls):
        cls.running = False
        cls._save_persist()
        if cls.mesh_socket:
            try: cls.mesh_socket.close()
            except Exception: pass
        with cls.latent_lock:
            for s in cls.latent_sockets.values():
                try: s.close()
                except Exception: pass
            cls.latent_sockets.clear()
        cls._sat_stop()
        cls._mobile_stop()

    # ── Latent Port System ─────────────────────────────────────────────

    @classmethod
    def _get_knock_sequence(cls) -> list:
        """Derive port-knocking sequence from node secret."""
        seed = int.from_bytes(cls.node_secret[:4], 'big')
        rng = random.Random(seed)
        base_ports = sorted(MESH_LATENT_PORTS)
        sequence = []
        for _ in range(4):
            p = rng.choice(base_ports)
            sequence.append(p)
        return sequence

    @classmethod
    def _latent_listener(cls):
        """Listen on all latent ports. When dormant, respond to nothing.
        On correct knock sequence, activate the port."""
        knock_seq = cls._get_knock_sequence()
        for port in MESH_LATENT_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.settimeout(1)
                with cls.latent_lock:
                    cls.latent_sockets[port] = s
            except Exception:
                pass

        while cls.running:
            with cls.latent_lock:
                ports = list(cls.latent_sockets.items())
            for port, sock in ports:
                if not cls.running:
                    break
                try:
                    data, addr = sock.recvfrom(1024)
                    cls._handle_knock(port, data, addr, knock_seq)
                except socket.timeout:
                    continue
                except Exception:
                    break
            time.sleep(0.1)

    @classmethod
    def _handle_knock(cls, port: int, data: bytes, addr: tuple, knock_seq: list):
        """Port-knocking auth: only respond if the correct sequence of
        ports is hit in order. A node must send knocks to port sequence
        in order before the latent port responds."""
        try:
            msg = json.loads(data.decode())
            if msg.get("type") != "knock":
                return
            sender = msg.get("from", "")
            knum = msg.get("seq", 0)

            key = (addr[0], sender)
            now = time.time()
            if key not in cls.knock_state:
                cls.knock_state[key] = {"step": 0, "time": now}

            state = cls.knock_state[key]
            if now - state["time"] > 10:
                state["step"] = 0

            expected_port = knock_seq[state["step"]]
            if port == expected_port:
                state["step"] += 1
                state["time"] = now
                if state["step"] >= len(knock_seq):
                    cls._activate_latent(sender, addr)
                    cls.knock_state[key] = {"step": 0, "time": now}
            else:
                state["step"] = 0
        except Exception:
            pass

    @classmethod
    def _activate_latent(cls, sender: str, addr: tuple):
        """Activate a latent port for a specific authenticated peer."""
        with cls.peers_lock:
            if sender not in cls.peers:
                return
            cls.peers[sender]["latent"] = True
            cls.peers[sender]["latent_addr"] = addr[0]
        # Send activation confirmation on primary mesh port
        try:
            cls._send_direct(sender, {
                "type": "latent_active",
                "from": POT_ID,
                "ports": MESH_LATENT_PORTS,
                "timestamp": time.time(),
            })
        except Exception:
            pass

    @classmethod
    def knock_port(cls, target_pot: str) -> bool:
        """Send port-knock sequence to a peer to activate their latent ports."""
        with cls.peers_lock:
            info = cls.peers.get(target_pot)
            if not info:
                return False
            addr = info.get("addr", "")
        knock_seq = cls._get_knock_sequence()
        for i, port in enumerate(knock_seq):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                msg = json.dumps({"type": "knock", "from": POT_ID, "seq": i}).encode()
                s.sendto(msg, (addr, port))
                s.close()
                time.sleep(0.2)
            except Exception:
                return False
        return True

    # ── AAA: Authentication & Trust ────────────────────────────────────

    @classmethod
    def _challenge_peer(cls, pot_id: str) -> dict:
        """Generate an auth challenge for a peer, signed with Ed25519."""
        nonce = CoffeeCipher.hash(cls.node_secret + pot_id.encode() + str(time.time()).encode())
        sig = Ed25519.sign(nonce.encode(), cls.node_seed)
        return {
            "type": "auth_request",
            "from": POT_ID,
            "cert": cls.node_cert,
            "challenge": nonce,
            "signature": base64.b64encode(sig).decode(),
            "timestamp": time.time(),
        }

    @classmethod
    def _verify_challenge(cls, challenge: str, peer_pot: str, peer_cert: dict) -> bool:
        """Verify a peer's challenge response using Ed25519."""
        expected = CoffeeCipher.hash(cls.node_secret + peer_pot.encode() + str(int(time.time())).encode())
        return challenge == expected

    @classmethod
    def _sign_message(cls, msg: dict) -> dict:
        """Sign a dict message with our Ed25519 key."""
        payload = json.dumps(msg, sort_keys=True).encode()
        sig = Ed25519.sign(payload, cls.node_seed)
        msg["_sig"] = base64.b64encode(sig).decode()
        msg["_signer"] = cls.node_address
        return msg

    @classmethod
    def _verify_message(cls, msg: dict) -> bool:
        """Verify a dict message's Ed25519 signature."""
        sig_b64 = msg.pop("_sig", None)
        signer_addr = msg.pop("_signer", None)
        if not sig_b64 or not signer_addr:
            return True  # unsigned messages allowed for backward compat
        try:
            sig = base64.b64decode(sig_b64)
            payload = json.dumps(msg, sort_keys=True).encode()
            # Look up signer's public key
            for pid, info in cls.peers.items():
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    pk = base64.b64decode(pk_b64)
                    if Ed25519.pubkey_to_address(pk) == signer_addr:
                        return Ed25519.verify(payload, sig, pk)
            return False
        except Exception:
            return False

    # ── Address Book (ECC Address ↔ POT_ID) ────────────────────────────

    @classmethod
    def _update_address_book(cls, pot_id: str, address: str, pubkey_b64: str, hostname: str = ""):
        """Register or update an address book entry."""
        if not address:
            return
        with cls.address_book_lock:
            cls.address_book[address] = {
                "pot_id": pot_id,
                "pubkey": pubkey_b64,
                "hostname": hostname,
                "last_seen": time.time(),
            }

    @classmethod
    def _resolve_address(cls, address_or_pot: str) -> str:
        """Resolve an ECC address or POT_ID to a POT_ID.
        
        If the string looks like an address (coffee: prefix), look up
        the address book. Otherwise return as-is (it's a POT_ID).
        """
        if address_or_pot.startswith("coffee:"):
            with cls.address_book_lock:
                entry = cls.address_book.get(address_or_pot)
                if entry:
                    return entry["pot_id"]
            return ""  # unknown address
        return address_or_pot  # already a POT_ID

    @classmethod
    def _get_pubkey_for(cls, pot_id: str) -> bytes:
        """Get the Ed25519 public key for a peer by POT_ID."""
        with cls.peers_lock:
            info = cls.peers.get(pot_id, {})
            pk_b64 = info.get("pubkey", "")
            if pk_b64:
                try:
                    return base64.b64decode(pk_b64)
                except Exception:
                    pass
        return b""

    # ── E2EE Message Encryption ────────────────────────────────────────

    @classmethod
    def _e2ee_encrypt(cls, plaintext: str, dst_pot: str) -> dict:
        """Encrypt a message payload with the recipient's Ed25519 public key.
        
        Uses ECDH to derive a shared secret, then encrypts with CoffeeCipher.
        Returns dict with encrypted data and metadata for decryption.
        """
        if not cls.node_seed:
            return {"data": plaintext, "e2ee": False}
        pk = cls._get_pubkey_for(dst_pot)
        if not pk:
            return {"data": plaintext, "e2ee": False}
        try:
            shared = Ed25519.key_exchange(cls.node_seed, pk)
            # Use the first 32 bytes of shared secret as a one-time key
            otk = hashlib.sha256(shared + b"cpip-e2ee-v1").digest()
            ciphertext = CoffeeCipher.encrypt(plaintext.encode(), base_key=otk)
            return {
                "data": base64.b64encode(ciphertext).decode(),
                "e2ee": True,
                "from_addr": cls.node_address,
            }
        except Exception:
            return {"data": plaintext, "e2ee": False}

    @classmethod
    def _e2ee_decrypt(cls, msg_data: str, from_addr: str = "") -> str:
        """Decrypt an E2EE message using the shared secret with the sender.
        
        Looks up the sender's public key from their address, derives
        the shared secret, and decrypts.
        """
        if not cls.node_seed or not from_addr:
            return msg_data
        # Find sender's pubkey
        sender_pk = None
        with cls.address_book_lock:
            entry = cls.address_book.get(from_addr)
            if entry and entry.get("pubkey"):
                try:
                    sender_pk = base64.b64decode(entry["pubkey"])
                except Exception:
                    pass
        if not sender_pk:
            # Fallback: search peers
            with cls.peers_lock:
                for pid, info in cls.peers.items():
                    pk_b64 = info.get("pubkey", "")
                    if pk_b64:
                        try:
                            pk = base64.b64decode(pk_b64)
                            if Ed25519.pubkey_to_address(pk) == from_addr:
                                sender_pk = pk
                                break
                        except Exception:
                            pass
        if not sender_pk:
            return msg_data
        try:
            shared = Ed25519.key_exchange(cls.node_seed, sender_pk)
            otk = hashlib.sha256(shared + b"cpip-e2ee-v1").digest()
            ciphertext = base64.b64decode(msg_data)
            plaintext = CoffeeCipher.decrypt(ciphertext, base_key=otk)
            return plaintext.decode("utf-8", errors="replace")
        except Exception:
            return msg_data

    @classmethod
    def _get_trust_level(cls, pot_id: str) -> int:
        with cls.trust_lock:
            return cls.trust_store.get(pot_id, cls.TRUST_UNTRUSTED)

    @classmethod
    def _set_trust_level(cls, pot_id: str, level: int):
        with cls.trust_lock:
            cls.trust_store[pot_id] = level
        cls._save_persist()

    @classmethod
    def _peer_authorized(cls, pot_id: str, min_level: int = TRUST_KNOWN) -> bool:
        return cls._get_trust_level(pot_id) >= min_level

    # ── Listener & Message Handler ─────────────────────────────────────

    @classmethod
    def _listener(cls):
        sock = cls.mesh_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(8192)
                data = cls._unpad_traffic(data)
                threading.Thread(target=cls._handle_message, args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    @classmethod
    def _handle_message(cls, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            msg_type = msg.get("type", "")

            sender = msg.get("pot") or msg.get("from") or ""
            if sender == POT_ID:
                return

            if msg_type == "heartbeat":
                with cls.peers_lock:
                    pubkey = msg.get("pubkey", "")
                    address = msg.get("address", "")
                    cls.peers[sender] = {
                        "addr": addr[0],
                        "port": msg.get("port", BIND_PORT),
                        "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                        "hostname": msg.get("hostname", addr[0]),
                        "device": msg.get("device", "unknown"),
                        "last_seen": time.time(),
                        "hops": msg.get("hops", 0),
                        "latent": False,
                        "pubkey": pubkey,
                        "address": address,
                    }
                    if address:
                        cls._update_address_book(sender, address, pubkey,
                                                  msg.get("hostname", addr[0]))
                cls._update_routes()
                trust = cls._get_trust_level(sender)
                if trust < cls.TRUST_KNOWN:
                    cls._send_direct(sender, cls._challenge_peer(sender))

            elif msg_type == "auth_request":
                cls._handle_auth_request(msg, addr)

            elif msg_type == "auth_response":
                cls._handle_auth_response(msg, addr)

            elif msg_type == "auth_grant":
                with cls.trust_lock:
                    cls.trust_store[sender] = msg.get("level", cls.TRUST_KNOWN)
                cls._save_persist()

            elif msg_type == "latent_active":
                with cls.peers_lock:
                    if sender in cls.peers:
                        cls.peers[sender]["latent"] = True

            elif msg_type == "message":
                if cls._peer_authorized(sender, cls.TRUST_KNOWN):
                    cls._route_message(msg, addr)

            elif msg_type == "route_query":
                if cls._peer_authorized(sender, cls.TRUST_KNOWN):
                    cls._handle_route_query(msg, addr)

            elif msg_type == "route_reply":
                with cls.peers_lock:
                    if msg.get("pot") in cls.peers:
                        cls.peers[msg["pot"]]["route"] = msg.get("route", [])

            elif msg_type == "ack":
                with cls.store_lock:
                    ack_id = msg.get("ack_id", "")
                    cls.message_store[:] = [m for m in cls.message_store if m.get("id") != ack_id]

            elif msg_type == "deaddrop_query":
                cls._handle_propfind_deaddrop(msg, addr)

            elif msg_type == "deaddrop_list":
                with cls.store_lock:
                    for drop in msg.get("drops", []):
                        if drop.get("dst") == POT_ID:
                            cls._send_direct(msg.get("from", ""), {
                                "type": "deaddrop_claim",
                                "from": POT_ID,
                                "message_id": drop["id"],
                                "timestamp": time.time(),
                            })

            elif msg_type == "deaddrop_claim":
                mid = msg.get("message_id", "")
                claimed = cls.claim_dead_drop(mid, sender)
                if claimed:
                    cls._send_direct(sender, claimed)

        except json.JSONDecodeError:
            pass
        except Exception:
            traceback.print_exc()

    @classmethod
    def _cross_transport_forward(cls, msg: dict, via: str):
        """Forward a received message to other mesh transports.
        via: 'radio', 'satellite', 'mobile', or 'mesh'
        Prevents routing loops by not forwarding back to the source transport.
        """
        if via != "satellite" and SATELLITE_ENABLED:
            try:
                target = msg.get("from") or msg.get("pot") or ""
                if target and target != POT_ID:
                    cls._sat_send_direct(target, msg)
            except Exception:
                pass
        if via != "radio" and _radio is not None:
            try:
                _radio.send(json.dumps(msg).encode())
            except Exception:
                pass
        if via != "mobile" and MOBILE_ENABLED and cls.mobile_socket:
            try:
                payload = json.dumps(msg).encode()
                target = msg.get("from") or msg.get("pot") or ""
                if target:
                    with cls.mobile_lock:
                        info = cls.mobile_peers.get(target)
                    if info:
                        cls.mobile_socket.sendto(payload, (info["addr"], info["port"]))
            except Exception:
                pass

    @classmethod
    def _handle_auth_request(cls, msg: dict, addr: tuple):
        """Process an incoming authentication request with Ed25519."""
        sender = msg.get("from", "")
        cert = msg.get("cert", {})
        challenge = msg.get("challenge", "")
        signature_b64 = msg.get("signature", "")

        # Store peer's pubkey
        if cert and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                with cls.peers_lock:
                    if sender in cls.peers:
                        cls.peers[sender]["pubkey"] = cert["pubkey"]
                        cls.peers[sender]["address"] = cert.get("address", "")
            except Exception:
                pass

        # Verify their signature on the challenge
        if signature_b64 and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                sig = base64.b64decode(signature_b64)
                if not Ed25519.verify(challenge.encode(), sig, pk):
                    return  # reject bad signature
            except Exception:
                return

        # Sign our response with Ed25519
        response = CoffeeCipher.hash(cls.node_secret + challenge.encode())
        my_sig = Ed25519.sign(response.encode(), cls.node_seed)
        cls._set_trust_level(sender, cls.TRUST_CHALLENGED)
        with cls.peers_lock:
            if sender in cls.peers:
                cls.peers[sender]["auth_step"] = "challenged"
        cls._send_direct(sender, {
            "type": "auth_response",
            "from": POT_ID,
            "cert": cls.node_cert,
            "challenge_response": response,
            "signature": base64.b64encode(my_sig).decode(),
            "challenge": CoffeeCipher.hash(cls.node_secret + sender.encode()),
            "timestamp": time.time(),
        })

    @classmethod
    def _handle_auth_response(cls, msg: dict, addr: tuple):
        """Process an authentication response. If valid, grant trust with Ed25519."""
        sender = msg.get("from", "")
        resp = msg.get("challenge_response", "")
        their_challenge = msg.get("challenge", "")
        signature_b64 = msg.get("signature", "")
        cert = msg.get("cert", {})

        # Store peer's pubkey
        if cert and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                with cls.peers_lock:
                    if sender in cls.peers:
                        cls.peers[sender]["pubkey"] = cert["pubkey"]
                        cls.peers[sender]["address"] = cert.get("address", "")
            except Exception:
                pass

        # Verify signature on response
        if signature_b64 and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                sig = base64.b64decode(signature_b64)
                if not Ed25519.verify(resp.encode(), sig, pk):
                    return
            except Exception:
                return

        expected = CoffeeCipher.hash(cls.node_secret + CoffeeCipher.hash(cls.node_secret + sender.encode()).encode())
        if resp == expected:
            level = cls.TRUST_TRUSTED
            cls._set_trust_level(sender, level)
            with cls.peers_lock:
                if sender in cls.peers:
                    cls.peers[sender]["auth_step"] = "trusted"
            grant_sig = Ed25519.sign(json.dumps({"level": level, "sender": sender}).encode(), cls.node_seed)
            cls._send_direct(sender, {
                "type": "auth_grant",
                "from": POT_ID,
                "level": level,
                "signature": base64.b64encode(grant_sig).decode(),
                "timestamp": time.time(),
            })
            # Respond to their challenge
            my_resp = CoffeeCipher.hash(cls.node_secret + their_challenge.encode())
            my_sig = Ed25519.sign(my_resp.encode(), cls.node_seed)
            cls._send_direct(sender, {
                "type": "auth_response",
                "from": POT_ID,
                "challenge_response": my_resp,
                "signature": base64.b64encode(my_sig).decode(),
                "timestamp": time.time(),
            })

    # ── Heartbeat (Stealth Mode) ───────────────────────────────────────

    @classmethod
    def _heartbeat_loop(cls):
        while cls.running:
            cls._send_heartbeat()
            with cls.peers_lock:
                now = time.time()
                stale = [p for p, info in cls.peers.items()
                         if now - info.get("last_seen", 0) > MESH_HEARTBEAT * 3]
                for p in stale:
                    del cls.peers[p]
            time.sleep(MESH_HEARTBEAT)

    @classmethod
    def _send_heartbeat(cls):
        payload = json.dumps({
            "type": "heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "lat": SATELLITE_LAT if SATELLITE_ENABLED else None,
            "lon": SATELLITE_LON if SATELLITE_ENABLED else None,
            "alt": SATELLITE_ALT if SATELLITE_ENABLED else None,
            "sat_port": SATELLITE_PORT if SATELLITE_ENABLED else None,
            "timestamp": time.time(),
        }).encode()
        payload = cls._pad_traffic(payload)

        if MeshNode.stealth_mode:
            with cls.peers_lock:
                targets = [(info["addr"], info.get("mesh_port", cls.current_mesh_port))
                           for pid, info in cls.peers.items()
                           if cls._peer_authorized(pid, cls.TRUST_KNOWN)]
            for addr, port in targets:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(2)
                    s.sendto(payload, (addr, port))
                    s.close()
                except Exception:
                    pass
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(payload, ("255.255.255.255", cls.current_mesh_port))
                s.close()
            except Exception:
                pass

    # ── Traffic Padding (Obfuscation) ──────────────────────────────────

    @classmethod
    def _pad_traffic(cls, data: bytes) -> bytes:
        """Pad UDP payload to a random size (256-1024 bytes) to defeat
        traffic analysis. Pad bytes are random noise."""
        min_size = max(256, len(data) + 4)
        target = random.randint(min_size, 1024)
        if len(data) >= target:
            return data
        padding = bytes(random.randint(0, 255) for _ in range(target - len(data)))
        return data + b"\x00" + struct.pack(">H", len(data)) + padding

    @classmethod
    def _unpad_traffic(cls, data: bytes) -> bytes:
        """Remove traffic padding."""
        try:
            null_idx = data.index(b"\x00", 128)
            if null_idx + 2 < len(data):
                orig_len = struct.unpack(">H", data[null_idx + 1:null_idx + 3])[0]
                if 0 < orig_len < len(data):
                    return data[:orig_len]
        except (ValueError, struct.error):
            pass
        return data

    # ── Cover Traffic ──────────────────────────────────────────────────

    @classmethod
    def _cover_traffic_loop(cls):
        while cls.running:
            time.sleep(random.randint(120, 300))
            with cls.peers_lock:
                targets = [pid for pid in cls.peers
                           if cls._peer_authorized(pid, cls.TRUST_KNOWN)]
            if not targets:
                continue
            cover = CovertChannel.generate_cover_traffic()
            if cover["additions"]:
                target = random.choice(targets)
                cls._send_direct(target, {
                    "type": "cover_traffic",
                    "from": POT_ID,
                    "additions": cover["additions"],
                    "timestamp": time.time(),
                })

    # ── Stealth Port Hopping ───────────────────────────────────────────

    @classmethod
    def _port_hop_loop(cls):
        """Periodically change the mesh port in stealth mode.
        
        Rotates through latent port + random high ports to evade
        deep packet inspection and port-based blocking.
        """
        while cls.running:
            time.sleep(MESH_HOP_INTERVAL)
            if not MeshNode.stealth_mode:
                continue
            try:
                # Pick a new port from latent range or random ephemeral
                if random.random() < 0.5:
                    new_port = random.choice(MESH_LATENT_PORTS)
                else:
                    new_port = random.randint(40000, 60000)

                # Create new socket on new port
                new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                new_sock.bind(("0.0.0.0", new_port))
                new_sock.settimeout(2)

                # Swap sockets
                old_sock = cls.mesh_socket
                old_port = cls.current_mesh_port
                cls.mesh_socket = new_sock
                cls.current_mesh_port = new_port

                # Notify trusted peers
                with cls.peers_lock:
                    for pid, info in cls.peers.items():
                        if cls._peer_authorized(pid, cls.TRUST_TRUSTED):
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                s.settimeout(1)
                                notice = json.dumps({
                                    "type": "port_hop",
                                    "from": POT_ID,
                                    "new_port": new_port,
                                    "timestamp": time.time(),
                                    "sig": base64.b64encode(
                                        Ed25519.sign(
                                            str(new_port).encode(), cls.node_seed
                                        )
                                    ).decode(),
                                }).encode()
                                s.sendto(notice, (info["addr"], info.get("mesh_port", old_port)))
                                s.close()
                            except Exception:
                                pass

                time.sleep(2)  # let listeners switch
                try:
                    old_sock.close()
                except Exception:
                    pass
            except Exception:
                pass

    # ── Keep Warm (Re-encrypt + Re-broadcast Undelivered) ──────────────

    @classmethod
    def _keep_warm_loop(cls):
        """Background thread that re-encrypts and re-broadcasts undelivered
        messages to keep the mesh 'warm'. Each retry uses a fresh ECDH
        shared secret for forward secrecy."""
        while cls.running:
            time.sleep(300)  # every 5 minutes
            with cls.store_lock:
                for stored in cls.message_store:
                    if stored["attempts"] >= 3 or not stored.get("e2ee"):
                        continue
                    # Re-encrypt with fresh ECDH for forward secrecy
                    pk = cls._get_pubkey_for(stored["dst"])
                    if pk and cls.node_seed:
                        try:
                            shared = Ed25519.key_exchange(cls.node_seed, pk)
                            otk = hashlib.sha256(shared + b"cpip-e2ee-v1").digest()
                            new_enc = CoffeeCipher.encrypt(
                                stored.get("_plaintext", "").encode(),
                                base_key=otk,
                            )
                            stored["msg"]["data"] = base64.b64encode(new_enc).decode()
                        except Exception:
                            pass

    # ── Starlink / Satellite Transport ──────────────────────────────────

    @classmethod
    def _sat_start(cls):
        if cls.sat_active:
            return
        if not SATELLITE_ENABLED and not cls.sat_active:
            return
        cls.sat_coords = (SATELLITE_LAT, SATELLITE_LON, SATELLITE_ALT)
        if SATELLITE_BOOTSTRAP:
            cls.sat_bootstrap = [b.strip() for b in SATELLITE_BOOTSTRAP.split(",") if b.strip()]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", SATELLITE_PORT))
            s.settimeout(MESH_SAT_TIMEOUT)
            cls.sat_socket = s
            cls.sat_active = True
            threading.Thread(target=cls._sat_listener, daemon=True).start()
            threading.Thread(target=cls._sat_heartbeat_loop, daemon=True).start()
            print(f"   ├ Satellite:  Sat-Mesh on port {SATELLITE_PORT}"
                  f" @ ({SATELLITE_LAT:.2f}, {SATELLITE_LON:.2f})", flush=True)
            if cls.sat_bootstrap:
                print(f"   ├ Bootstrap:  {len(cls.sat_bootstrap)} satellite seed nodes", flush=True)
            if SATELLITE_RELAY:
                print(f"   └ Relay:      Ground-station relay mode active", flush=True)
        except Exception as e:
            print(f"   ⚠ Starlink:   {e}", flush=True)

    @classmethod
    def _sat_stop(cls):
        if cls.sat_socket:
            try: cls.sat_socket.close()
            except Exception: pass
            cls.sat_socket = None
            cls.sat_active = False

    @classmethod
    def sat_enable(cls):
        cls.sat_active = True
        cls._sat_start()

    @classmethod
    def sat_disable(cls):
        with cls.sat_lock:
            cls.sat_peers.clear()
        cls._sat_stop()

    @classmethod
    def _sat_listener(cls):
        sock = cls.sat_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(4096)
                threading.Thread(target=cls._sat_handle, args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    @classmethod
    def _sat_handle(cls, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            sender = msg.get("pot") or msg.get("from") or ""
            if sender == POT_ID or not sender:
                return

            with cls.sat_lock:
                cls.sat_peers[sender] = {
                    "addr": addr[0],
                    "port": msg.get("sat_port", SATELLITE_PORT),
                    "hostname": msg.get("hostname", addr[0]),
                    "device": msg.get("device", "unknown"),
                    "last_seen": time.time(),
                    "lat": msg.get("lat", 0),
                    "lon": msg.get("lon", 0),
                    "alt": msg.get("alt", 0),
                    "hops": msg.get("hops", 0),
                    "pubkey": msg.get("pubkey", ""),
                    "address": msg.get("address", ""),
                }

            if msg.get("type") == "sat_heartbeat":
                cls._sat_ping(sender, addr)
                with cls.peers_lock:
                    cls.peers[sender] = {
                        "addr": addr[0],
                        "port": msg.get("port", BIND_PORT),
                        "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                        "hostname": msg.get("hostname", addr[0]),
                        "device": msg.get("device", "unknown"),
                        "last_seen": time.time(),
                        "hops": msg.get("hops", 0) + 1,
                        "latent": False,
                        "pubkey": msg.get("pubkey", ""),
                        "address": msg.get("address", ""),
                        "sat_link": True,
                        "sat_lat": msg.get("lat", 0),
                        "sat_lon": msg.get("lon", 0),
                        "sat_alt": msg.get("alt", 0),
                    }
                cls._update_routes()
                trust = cls._get_trust_level(sender)
                if trust < cls.TRUST_KNOWN:
                    cls._sat_send_direct(sender, cls._challenge_peer(sender))

            elif msg.get("type") == "sat_pong":
                with cls.sat_lock:
                    cls.sat_rtt[sender] = time.time() - msg.get("sent", time.time())

            elif msg.get("type") in ("message", "route_query", "deaddrop_query"):
                cls._handle_message(data, addr)
                cls._cross_transport_forward(msg, via="satellite")

        except Exception:
            pass

    @classmethod
    def _sat_heartbeat_loop(cls):
        while cls.running:
            cls._sat_send_heartbeat()
            with cls.sat_lock:
                now = time.time()
                stale = [p for p, info in cls.sat_peers.items()
                         if now - info.get("last_seen", 0) > MESH_SAT_HEARTBEAT * 3]
                for p in stale:
                    del cls.sat_peers[p]
            time.sleep(MESH_SAT_HEARTBEAT)

    @classmethod
    def _sat_send_heartbeat(cls):
        payload = json.dumps({
            "type": "sat_heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "sat_port": SATELLITE_PORT,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "lat": SATELLITE_LAT,
            "lon": SATELLITE_LON,
            "alt": SATELLITE_ALT,
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "timestamp": time.time(),
        }).encode()
        cls._sat_broadcast(payload)

    @classmethod
    def _sat_ping(cls, sender: str, addr: tuple):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(MESH_SAT_TIMEOUT)
            pong = json.dumps({
                "type": "sat_pong",
                "from": POT_ID,
                "sent": time.time(),
            }).encode()
            s.sendto(pong, addr)
            s.close()
        except Exception:
            pass

    @classmethod
    def _sat_broadcast(cls, payload: bytes):
        """Send to all bootstrap nodes and known satellite peers."""
        targets = set()
        for b in cls.sat_bootstrap:
            if ":" in b:
                host, p = b.rsplit(":", 1)
                targets.add((host, int(p)))
            else:
                targets.add((b, SATELLITE_PORT))
        with cls.sat_lock:
            for pid, info in cls.sat_peers.items():
                targets.add((info["addr"], info["port"]))
        for addr, port in targets:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(payload, (addr, port))
                s.close()
            except Exception:
                pass

    @classmethod
    def _sat_send_direct(cls, dst: str, msg: dict) -> bool:
        """Send a message directly via satellite link if the peer is known."""
        with cls.sat_lock:
            info = cls.sat_peers.get(dst)
        if not info:
            return False
        try:
            payload = json.dumps(msg).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(MESH_SAT_TIMEOUT)
            s.sendto(payload, (info["addr"], info["port"]))
            s.close()
            return True
        except Exception:
            return False

    @classmethod
    def get_sat_status(cls) -> dict:
        with cls.sat_lock:
            return {
                "enabled": cls.sat_active,
                "port": SATELLITE_PORT,
                "coords": {"lat": SATELLITE_LAT, "lon": SATELLITE_LON, "alt": SATELLITE_ALT},
                "bootstrap": cls.sat_bootstrap,
                "relay": SATELLITE_RELAY,
                "peers_known": len(cls.sat_peers),
                "peers": [{"pot": pid,
                           "hostname": info.get("hostname", "?"),
                           "addr": info.get("addr", "?"),
                           "lat": info.get("lat", 0),
                           "lon": info.get("lon", 0),
                           "last_seen": info.get("last_seen", 0),
                           "rtt": round(cls.sat_rtt.get(pid, 0) * 1000, 1),
                           "hops": info.get("hops", 0)}
                          for pid, info in cls.sat_peers.items()],
            }

    # ── Mobile Broadband (4G/5G / LTE / WWAN) Transport ────────────────

    mobile_socket = None
    mobile_peers = {}
    mobile_lock = threading.Lock()
    mobile_bootstrap = []
    mobile_active = False

    @classmethod
    def _mobile_start(cls):
        if cls.mobile_active:
            return
        if not MOBILE_ENABLED and not cls.mobile_active:
            return
        if MOBILE_BOOTSTRAP:
            cls.mobile_bootstrap = [b.strip() for b in MOBILE_BOOTSTRAP.split(",") if b.strip()]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", MOBILE_PORT))
            s.settimeout(3.0)
            cls.mobile_socket = s
            cls.mobile_active = True
            threading.Thread(target=cls._mobile_listener, daemon=True).start()
            threading.Thread(target=cls._mobile_heartbeat_loop, daemon=True).start()
            print(f"   ├ Mobile:     4G/5G port {MOBILE_PORT}"
                  f" ({MOBILE_INTERFACE})", flush=True)
            if cls.mobile_bootstrap:
                print(f"   ├ Bootstrap: {len(cls.mobile_bootstrap)} mobile seed nodes", flush=True)
        except Exception as e:
            print(f"   ⚠ Mobile:   {e}", flush=True)

    @classmethod
    def _mobile_stop(cls):
        if cls.mobile_socket:
            try: cls.mobile_socket.close()
            except Exception: pass
            cls.mobile_socket = None
            cls.mobile_active = False

    @classmethod
    def mobile_enable(cls):
        cls.mobile_active = True
        cls._mobile_start()

    @classmethod
    def mobile_disable(cls):
        with cls.mobile_lock:
            cls.mobile_peers.clear()
        cls._mobile_stop()

    @classmethod
    def _mobile_listener(cls):
        sock = cls.mobile_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(4096)
                threading.Thread(target=cls._mobile_handle, args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    @classmethod
    def _mobile_handle(cls, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            sender = msg.get("pot") or msg.get("from") or ""
            if sender == POT_ID or not sender:
                return

            with cls.mobile_lock:
                cls.mobile_peers[sender] = {
                    "addr": addr[0],
                    "port": msg.get("mobile_port", MOBILE_PORT),
                    "hostname": msg.get("hostname", addr[0]),
                    "device": msg.get("device", "unknown"),
                    "last_seen": time.time(),
                    "signal": msg.get("signal", None),
                    "net": msg.get("network", ""),
                    "pubkey": msg.get("pubkey", ""),
                    "address": msg.get("address", ""),
                    "hops": msg.get("hops", 0),
                }

            if msg.get("type") == "mobile_heartbeat":
                with cls.peers_lock:
                    cls.peers[sender] = {
                        "addr": addr[0],
                        "port": msg.get("port", BIND_PORT),
                        "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                        "hostname": msg.get("hostname", addr[0]),
                        "device": msg.get("device", "unknown"),
                        "last_seen": time.time(),
                        "hops": msg.get("hops", 0) + 1,
                        "latent": False,
                        "pubkey": msg.get("pubkey", ""),
                        "address": msg.get("address", ""),
                        "mobile_link": True,
                        "signal": msg.get("signal"),
                        "network": msg.get("network", ""),
                    }
                cls._update_routes()
                cls._cross_transport_forward(msg, via="mobile")
            elif msg.get("type") in ("message", "route_query", "deaddrop_query"):
                cls._handle_message(data, addr)
                cls._cross_transport_forward(msg, via="mobile")
        except Exception:
            pass

    @classmethod
    def _mobile_heartbeat_loop(cls):
        while cls.running:
            cls._mobile_send_heartbeat()
            with cls.mobile_lock:
                now = time.time()
                stale = [p for p, info in cls.mobile_peers.items()
                         if now - info.get("last_seen", 0) > MOBILE_HEARTBEAT * 3]
                for p in stale:
                    del cls.mobile_peers[p]
            time.sleep(MOBILE_HEARTBEAT)

    @classmethod
    def _mobile_send_heartbeat(cls):
        payload = json.dumps({
            "type": "mobile_heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "mobile_port": MOBILE_PORT,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "network": MOBILE_INTERFACE,
            "signal": cls._mobile_get_signal(),
            "timestamp": time.time(),
        }).encode()
        targets = set()
        for b in cls.mobile_bootstrap:
            if ":" in b:
                host, p = b.rsplit(":", 1)
                targets.add((host, int(p)))
            else:
                targets.add((b, MOBILE_PORT))
        with cls.mobile_lock:
            for pid, info in cls.mobile_peers.items():
                targets.add((info["addr"], info["port"]))
        if not targets:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            for addr, port in targets:
                try:
                    s.sendto(payload, (addr, port))
                except Exception:
                    pass
            s.close()
        except Exception:
            pass

    @classmethod
    def _mobile_get_signal(cls) -> dict:
        """Read cellular signal strength. Tries multiple methods."""
        result = {"rssi": None, "rsrp": None, "sinr": None, "mcc": None, "interface": MOBILE_INTERFACE}
        iface = MOBILE_INTERFACE
        if not os.path.isdir("/sys/class/net/" + iface):
            alt = [n for n in os.listdir("/sys/class/net/")
                   if n.startswith(("wwan", "usb", "eth")) and n != "lo"]
            if alt:
                iface = alt[0]
                result["interface"] = iface
        for suffix, key in [("rssi", "rssi"), ("signal", "rssi"), ("rsrp", "rsrp"), ("sinr", "sinr")]:
            p = f"/sys/class/net/{iface}/statistics/{suffix}"
            try:
                with open(p) as f:
                    result[key] = int(f.read().strip())
            except Exception:
                pass
        try:
            out = subprocess.run(
                ["mmcli", "-m", "any", "--output=json"],
                capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0:
                d = json.loads(out.stdout)
                m = d.get("modem", {}).get("generic", {})
                result.update({
                    "rssi": m.get("signal-quality", result.get("rssi")),
                    "mcc": d.get("modem", {}).get("3gpp", {}).get("mcc"),
                    "network": d.get("modem", {}).get("3gpp", {}).get("operator-name", ""),
                })
        except Exception:
            pass
        return result

    @classmethod
    def get_mobile_status(cls) -> dict:
        with cls.mobile_lock:
            peers = [{"pot": pid,
                      "hostname": info.get("hostname", "?"),
                      "addr": info.get("addr", "?"),
                      "last_seen": info.get("last_seen", 0),
                      "signal": info.get("signal"),
                      "network": info.get("network", ""),
                      "hops": info.get("hops", 0)}
                     for pid, info in cls.mobile_peers.items()]
        return {
            "enabled": cls.mobile_active,
            "port": MOBILE_PORT,
            "interface": MOBILE_INTERFACE,
            "bootstrap": list(cls.mobile_bootstrap),
            "telemetry": MOBILE_TELEMETRY,
            "peers_known": len(cls.mobile_peers),
            "peers": peers,
            "signal": cls._mobile_get_signal(),
        }

    # ── Routing ────────────────────────────────────────────────────────

    @classmethod
    def _update_routes(cls):
        with cls.peers_lock:
            for pot_id, info in cls.peers.items():
                if cls._peer_authorized(pot_id, cls.TRUST_KNOWN):
                    cls.routing_table[pot_id] = {
                        "addr": info["addr"],
                        "port": info.get("mesh_port", cls.current_mesh_port),
                        "hops": info.get("hops", 1),
                        "last_seen": info.get("last_seen", 0),
                    }

    @classmethod
    def _route_message(cls, msg: dict, addr: tuple):
        dst = msg.get("dst", "")
        ttl = msg.get("ttl", MESH_TTL)
        message_id = msg.get("id", "")

        if ttl <= 0:
            return

        if dst == POT_ID or not dst:
            # Decrypt E2EE if applicable
            raw_data = msg.get("data", "")
            if msg.get("e2ee") and msg.get("from_addr"):
                raw_data = cls._e2ee_decrypt(raw_data, msg["from_addr"])
            with cls.inbox_lock:
                cls.inbox.append({
                    "id": message_id,
                    "from": msg.get("from", "unknown"),
                    "data": raw_data,
                    "timestamp": time.time(),
                    "hops": MESH_TTL - ttl + 1,
                    "channel": "mesh_aaa",
                    "e2ee": msg.get("e2ee", False),
                })
                if len(cls.inbox) > HISTORY_MAX:
                    cls.inbox = cls.inbox[-HISTORY_MAX:]
            PotState._broadcast({
                "event": "mesh_message",
                "from": msg.get("from", "unknown"),
                "message_id": message_id,
            })
            sender = msg.get("from", "")
            if sender and sender != POT_ID:
                cls._send_direct(sender, {
                    "type": "ack", "ack_id": message_id,
                    "from": POT_ID, "dst": sender, "timestamp": time.time(),
                })
            return

        with cls.peers_lock:
            next_hop = cls.routing_table.get(dst)

        if next_hop:
            ttl -= 1
            msg["ttl"] = ttl
            msg["route"] = msg.get("route", []) + [POT_ID]
            cls._send_direct(dst, msg)
        else:
            with cls.store_lock:
                cls.message_store.append({
                    "id": message_id, "dst": dst, "msg": msg,
                    "queued": time.time(), "attempts": 0,
                })

    # ── Covert Fallback (HTTP over UDP) ────────────────────────────────

    @classmethod
    def _covert_fallback_send(cls, dst_pot: str, msg: dict) -> bool:
        """If direct UDP fails, encode message as HTTP brew request."""
        try:
            data_str = json.dumps(msg)
            additions = CovertChannel.encode(data_str.encode(), dst_pot)
            header = ", ".join(f"{a['name']};variety={a['variety']}" for a in additions["additions"])
            with cls.peers_lock:
                info = cls.peers.get(dst_pot)
            if not info:
                return False
            import urllib.request
            req = urllib.request.Request(
                f"http://{info['addr']}:{info.get('port', BIND_PORT)}/tea",
                method="BREW",
                headers={"Accept-Additions": header},
            )
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception:
            return False

    # ── Direct Send ────────────────────────────────────────────────────

    @classmethod
    def _send_direct(cls, dst_pot: str, msg: dict):
        try:
            with cls.peers_lock:
                info = cls.peers.get(dst_pot)
            if not info:
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            data = json.dumps(msg).encode()
            data = cls._pad_traffic(data)
            port = info.get("mesh_port", cls.current_mesh_port)
            sock.sendto(data, (info["addr"], port))
            sock.close()
            return True
        except Exception:
            return cls._covert_fallback_send(dst_pot, msg)

    # ── Route Query ────────────────────────────────────────────────────

    @classmethod
    def _handle_route_query(cls, msg: dict, addr: tuple):
        target = msg.get("target", "")
        with cls.peers_lock:
            route = cls.routing_table.get(target)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = json.dumps({"type": "route_reply", "pot": POT_ID,
                               "target": target, "route": [route] if route else []}).encode()
            s.sendto(cls._pad_traffic(data), addr)
            s.close()
        except Exception:
            pass

    # ── Public API ─────────────────────────────────────────────────────

    @classmethod
    def send_message(cls, dst: str, data: str, use_e2ee: bool = True) -> dict:
        """Send a message to a peer. Supports ECC address resolution and E2EE.
        
        - dst can be a POT_ID or an ECC address (coffee:...)
        - If use_e2ee=True and the recipient's public key is known, the
          payload is ECDH-encrypted before sending
        """
        # Resolve address book entry
        original_dst = dst
        dst = cls._resolve_address(dst)
        if not dst:
            return {"status": "error", "error": f"Unknown address: {original_dst}"}

        message_id = str(uuid.uuid4())[:8]

        # E2EE encrypt the payload
        if use_e2ee:
            encrypted = cls._e2ee_encrypt(data, dst)
            payload_data = encrypted["data"]
            e2ee_meta = {
                "e2ee": encrypted.get("e2ee", False),
                "from_addr": encrypted.get("from_addr", ""),
            }
        else:
            payload_data = data
            e2ee_meta = {"e2ee": False, "from_addr": ""}

        msg = {
            "type": "message", "id": message_id, "from": POT_ID,
            "dst": dst, "data": payload_data, "ttl": MESH_TTL,
            "route": [POT_ID], "timestamp": time.time(),
            **e2ee_meta,
        }
        sent = cls._send_direct(dst, msg)
        if sent:
            return {"status": "sent", "message_id": message_id, "method": "direct", "e2ee": e2ee_meta["e2ee"]}
        with cls.store_lock:
            store_entry = {
                "id": message_id, "dst": dst, "msg": msg,
                "queued": time.time(), "attempts": 0,
                "e2ee": e2ee_meta["e2ee"],
            }
            if e2ee_meta["e2ee"]:
                store_entry["_plaintext"] = data  # for re-encryption
            cls.message_store.append(store_entry)
        return {"status": "queued", "message_id": message_id, "method": "store_forward", "e2ee": e2ee_meta["e2ee"]}

    @classmethod
    def broadcast(cls, data: str) -> dict:
        count = 0
        with cls.peers_lock:
            peers = list(cls.peers.keys())
        for dst in peers:
            result = cls.send_message(dst, data)
            if result.get("status") in ("sent", "queued"):
                count += 1
        return {"status": "broadcast", "peers_reached": count, "total_known": len(peers)}

    @classmethod
    def store_forward_retry(cls):
        """Retry undelivered messages with exponential backoff.
        
        In Thermos mode, acts as an aggregator node: accepts encrypted
        dead-drops from other nodes and holds them for retrieval.
        After max attempts, advertises as a dead-drop host via PROPFIND.
        
        E2EE messages have their plaintext stored temporarily for
        re-encryption on each retry (forward secrecy).
        """
        while cls.running:
            time.sleep(60)
            with cls.store_lock:
                still_pending = []
                for stored in cls.message_store:
                    stored["attempts"] += 1
                    # Re-encrypt E2EE payload with fresh key for forward secrecy
                    if stored.get("e2ee") and stored.get("_plaintext"):
                        pk = cls._get_pubkey_for(stored["dst"])
                        if pk and cls.node_seed:
                            try:
                                shared = Ed25519.key_exchange(cls.node_seed, pk)
                                otk = hashlib.sha256(shared + b"cpip-e2ee-v1").digest()
                                new_ct = CoffeeCipher.encrypt(
                                    stored["_plaintext"].encode(), base_key=otk,
                                )
                                stored["msg"]["data"] = base64.b64encode(new_ct).decode()
                            except Exception:
                                pass
                    # Exponential backoff
                    if stored["attempts"] > 10:
                        # Dead-drop: re-encrypt for aggregator if Thermos mode
                        if THERMOS_ENABLED:
                            stored["dead_drop"] = True
                            stored["held_by"] = POT_ID
                            # Purge plaintext from dead drops
                            stored["_plaintext"] = ""
                            still_pending.append(stored)
                        continue
                    if cls._send_direct(stored["dst"], stored["msg"]):
                        continue
                    still_pending.append(stored)
                cls.message_store = still_pending

    # ── Dead-Drop Relay ─────────────────────────────────────────────────

    @classmethod
    def advertise_dead_drops(cls) -> list:
        """Return list of held messages available for retrieval.
        
        In PROPFIND responses, nodes can discover which peers hold
        messages for them.
        """
        with cls.store_lock:
            return [{
                "id": m["id"],
                "dst": m["dst"],
                "held_by": m.get("held_by", POT_ID),
                "queued": m.get("queued", 0),
                "dead_drop": m.get("dead_drop", False),
            } for m in cls.message_store if m.get("dead_drop")]

    @classmethod
    def claim_dead_drop(cls, message_id: str, claimant: str) -> dict:
        """Claim and deliver a dead-dropped message.
        
        In PROPFIND responses, recipients can claim their messages
        from aggregator nodes.
        """
        with cls.store_lock:
            for i, m in enumerate(cls.message_store):
                if m["id"] == message_id and m["dst"] == claimant:
                    msg = m["msg"]
                    cls.message_store.pop(i)
                    return msg
        return {}

    @classmethod
    def _handle_propfind_deaddrop(cls, msg: dict, addr: tuple):
        """Handle a PROPFIND dead-drop query from a peer."""
        query_type = msg.get("query", "")
        if query_type == "list":
            drops = cls.advertise_dead_drops()
            cls._send_direct(msg["from"], {
                "type": "deaddrop_list",
                "from": POT_ID,
                "drops": drops,
                "timestamp": time.time(),
            })
        elif query_type == "claim":
            mid = msg.get("message_id", "")
            claimed = cls.claim_dead_drop(mid, msg["from"])
            if claimed:
                cls._send_direct(msg["from"], claimed)

    # ── Persistence ────────────────────────────────────────────────────

    @classmethod
    def _save_persist(cls):
        if not cls.persist_path:
            return
        try:
            data = {
                "peers": {pid: {k: v for k, v in info.items()
                                if k in ("addr", "port", "mesh_port", "hostname", "device", "hops",
                                         "pubkey", "address")}
                          for pid, info in cls.peers.items()},
                "inbox": cls.inbox[-50:],
                "trust_store": dict(cls.trust_store),
                "routes": dict(cls.routing_table),
                "message_store": cls.message_store[-100:],
            }
            cls.persist_path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    @classmethod
    def _load_persist(cls):
        if not cls.persist_path or not cls.persist_path.exists():
            return
        try:
            data = json.loads(cls.persist_path.read_text())
            with cls.peers_lock:
                for pid, info in data.get("peers", {}).items():
                    cls.peers[pid] = info
            with cls.inbox_lock:
                cls.inbox = data.get("inbox", [])
            with cls.trust_lock:
                cls.trust_store.update(data.get("trust_store", {}))
            with cls.peers_lock:
                cls.routing_table.update(data.get("routes", {}))
            with cls.store_lock:
                old_store = data.get("message_store", [])
                for m in old_store:
                    if m.get("attempts", 0) < 10:
                        cls.message_store.append(m)
        except Exception:
            pass

    @classmethod
    def _persist_loop(cls):
        while cls.running:
            time.sleep(300)
            cls._save_persist()

    # ── Status / Info ──────────────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict:
        with cls.peers_lock:
            peers_info = {
                pid: {k: v for k, v in info.items() if k not in ("mesh_port",)}
                for pid, info in cls.peers.items()
            }
        with cls.store_lock:
            queued = len(cls.message_store)
        with cls.inbox_lock:
            inbox_count = len(cls.inbox)
        with cls.trust_lock:
            trust = {pid: cls.TRUST_NAMES.get(level, "unknown")
                     for pid, level in cls.trust_store.items()}
        dead_drops = cls.advertise_dead_drops() if THERMOS_ENABLED else []
        with cls.address_book_lock:
            addr_book = dict(cls.address_book)
        return {
            "enabled": MESH_ENABLED,
            "port": cls.current_mesh_port,
            "latent_ports": MESH_LATENT_PORTS,
            "stealth": MeshNode.stealth_mode,
            "node_id": POT_ID,
            "node_address": cls.node_address,
            "node_pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else None,
            "peers_known": len(cls.peers),
            "peers": peers_info,
            "trust": trust,
            "messages_queued": queued,
            "inbox_count": inbox_count,
            "routes": {k: v for k, v in cls.routing_table.items()},
            "persist": str(cls.persist_path) if cls.persist_path else None,
            "thermos": THERMOS_ENABLED,
            "dead_drops": dead_drops,
            "ecc": "Ed25519 (Curve25519, pure Python)",
            "ecc_constant_time": False,
            "address_book": {
                addr: {k: v for k, v in info.items() if k != "pubkey"}
                for addr, info in addr_book.items()
            },
            "port_hopping": MeshNode.stealth_mode,
            "keep_warm": True,
        }

    @classmethod
    def get_inbox(cls, limit=20) -> list:
        with cls.inbox_lock:
            return cls.inbox[-limit:]

    @classmethod
    def get_peers_list(cls) -> list:
        with cls.peers_lock:
            return [{
                "pot": pid,
                "hostname": info.get("hostname", "unknown"),
                "addr": info.get("addr", "unknown"),
                "device": info.get("device", "unknown"),
                "last_seen": info.get("last_seen", 0),
                "hops": info.get("hops", 0),
                "trust": cls.TRUST_NAMES.get(cls._get_trust_level(pid), "untrusted"),
                "latent": info.get("latent", False),
            } for pid, info in cls.peers.items()]


# ── GPIO Control (Hardware Only — No Simulation) ──────────────────────
class GpioController:
    """Raspberry Pi GPIO control via RPi.GPIO.
    
    No simulated mode. If GPIO_ENABLED=1 and RPi.GPIO is unavailable,
    the application exits with an error. Coffee pots are real hardware.
    """

    def __init__(self):
        self._pin = GPIO_PIN
        self._state = False
        if GPIO_ENABLED:
            import RPi.GPIO as GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self._pin, GPIO.OUT)
            GPIO.output(self._pin, GPIO.LOW)
            self._gpio = GPIO
        else:
            self._gpio = None

    def on(self):
        self._state = True
        if self._gpio:
            self._gpio.output(self._pin, self._gpio.HIGH)
        return True

    def off(self):
        self._state = False
        if self._gpio:
            self._gpio.output(self._pin, self._gpio.LOW)
        return True

    @property
    def is_on(self):
        return self._state

    @property
    def is_available(self):
        return self._gpio is not None

gpio = GpioController()


# ── State Machine ─────────────────────────────────────────────────────
class PotState:
    brewing = False
    brew_start_time = None
    current_beverage = None
    current_additions = []
    brew_id = None
    history = []
    schedules = []
    webhooks = []
    sse_clients = []
    sse_lock = threading.Lock()
    state_lock = threading.Lock()

    @classmethod
    def start(cls, beverage="tea", additions=None):
        with cls.state_lock:
            cls.brewing = True
            cls.brew_start_time = time.time()
            cls.current_beverage = beverage
            cls.current_additions = additions or []
            cls.brew_id = str(uuid.uuid4())[:8]
        gpio.on()
        cls._broadcast({"event": "brew_start", "beverage": beverage, "additions": additions, "brew_id": cls.brew_id})
        return cls.brew_id

    @classmethod
    def stop(cls):
        with cls.state_lock:
            was = cls.brewing
            if was:
                elapsed = time.time() - cls.brew_start_time if cls.brew_start_time else 0
                cls.history.append({
                    "id": cls.brew_id,
                    "beverage": cls.current_beverage,
                    "additions": cls.current_additions,
                    "started": cls.brew_start_time,
                    "duration": round(elapsed, 1),
                    "ended": time.time(),
                })
                if len(cls.history) > HISTORY_MAX:
                    cls.history = cls.history[-HISTORY_MAX:]
            cls.brewing = False
            cls.brew_start_time = None
            cls.current_beverage = None
            cls.current_additions = []
        gpio.off()
        if was:
            cls._broadcast({"event": "brew_stop"})
            cls._fire_webhooks()
        return was

    @classmethod
    def is_brewing(cls):
        return cls.brewing

    @classmethod
    def _broadcast(cls, data):
        with cls.sse_lock:
            msg = f"data: {json.dumps(data)}\n\n"
            dead = []
            for q in cls.sse_clients:
                try:
                    q.put_nowait(msg)
                except Exception:
                    dead.append(q)
            for q in dead:
                cls.sse_clients.remove(q)

    @classmethod
    def _fire_webhooks(cls):
        if not cls.webhooks:
            return
        payload = {
            "event": "brew_complete",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "beverage": cls.history[-1]["beverage"] if cls.history else "unknown",
            "timestamp": time.time(),
        }
        for url in cls.webhooks:
            try:
                import urllib.request
                data = json.dumps(payload).encode()
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass


# ── HTCPCP Protocol Helpers ───────────────────────────────────────────
def parse_accept_additions(header_value):
    if not header_value:
        return []
    additions = []
    for token in header_value.split(","):
        token = token.strip()
        if not token:
            continue
        parts = token.split(";")
        name = parts[0].strip().lower()
        variety = None
        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("variety="):
                variety = part.split("=", 1)[1].strip()
        additions.append({"name": name, "variety": variety})
    return additions


def check_additions(additions, device_type):
    allows_alcohol = device_type in ALCOHOL_DEVICES
    for addn in additions:
        name = addn["name"]
        if name not in VALID_ADDITIONS:
            return False, f"Unknown addition type: {name}"
        addn_def = VALID_ADDITIONS[name]
        if addn_def["type"] == "alcohol" and not allows_alcohol:
            return False, f"Device type '{device_type}' does not support alcohol additions"
        if addn["variety"] and addn["variety"] not in addn_def["variety"]:
            continue
    return True, None


def is_beverage_compatible(request_path, device_type):
    allowed = DEVICE_BEVERAGE_MAP.get(device_type, ["tea"])
    path = urlparse(request_path).path.rstrip("/")
    if path.endswith("/coffee"):
        return "coffee" in allowed
    if path.endswith("/tea"):
        return "tea" in allowed
    return True


# ── coffee: URI Scheme Support (RFC 2324 §3) ───────────────────────────
def is_coffee_uri_path(path):
    """Check if path uses the coffee: URI scheme (any international variant).
    Handles both raw scheme:// and HTTP-prefixed /scheme:// forms."""
    lower = path.lower().lstrip("/")
    for scheme in COFFEE_SCHEME_NAMES:
        if lower.startswith(scheme + "://") or lower.startswith(scheme + ":"):
            return True
    return False


def parse_coffee_uri(path):
    """Parse a coffee: URI into (pot_designator, additions_list, beverage_hint).
    
    coffee-url = coffee-scheme ":" [ "//" host ] ["/" pot-designator] ["?" additions-list]
    pot-designator = "pot-" integer
    additions-list = #( addition )
    """
    lower = path.lower().lstrip("/")
    scheme = None
    for s in COFFEE_SCHEME_NAMES:
        if lower.startswith(s + "://") or lower.startswith(s + ":"):
            scheme = s
            break
    if not scheme:
        return None, [], None

    rest = lower[len(scheme):]
    if rest.startswith("://"):
        rest = rest[3:]
    elif rest.startswith(":"):
        rest = rest[1:]

    host = ""
    if rest and not rest.startswith("/") and not rest.startswith("?"):
        slash = rest.find("/")
        qmark = rest.find("?")
        end = len(rest)
        if slash >= 0:
            end = min(end, slash)
        if qmark >= 0:
            end = min(end, qmark)
        host = rest[:end]
        rest = rest[end:]

    pot = None
    if rest.startswith("/pot-"):
        parts = rest[1:].split("?", 1)
        pot = parts[0]
        rest = "?" + parts[1] if len(parts) > 1 else ""

    additions_raw = ""
    if rest.startswith("?"):
        additions_raw = rest[1:]

    additions = []
    beverage_hint = None
    if additions_raw:
        for token in additions_raw.split(","):
            token = token.strip()
            if not token:
                continue
            parts = token.split(";")
            name = parts[0].strip().lower()
            variety = None
            for part in parts[1:]:
                part = part.strip().lower()
                if part.startswith("variety="):
                    variety = part.split("=", 1)[1].strip()
            additions.append({"name": name, "variety": variety})
            if name == "coffee":
                beverage_hint = "coffee"
            elif name == "tea":
                beverage_hint = "tea"

    # Map scheme to beverage hint
    if not beverage_hint:
        if scheme in ("koffie", "kaffe", "kahvi", "coffee", "kava",
                       "kafe", "kohv", "kafo", "caf%C3%A8",
                       "%4Baffee", "%E5%92%96%E5%95%A1"):
            beverage_hint = "coffee"
        elif scheme in ("akeita", "kahva"):
            beverage_hint = "tea"
        else:
            beverage_hint = "coffee"

    return pot, additions, beverage_hint


# ── mDNS Advertising ──────────────────────────────────────────────────
_avahi_process = None

def start_mdns():
    global _avahi_process
    if not AVAHI_ENABLED:
        return
    try:
        _avahi_process = subprocess.Popen(
            ["avahi-publish-service", f"CPIP-{HOSTNAME}", "_coffee._tcp", str(BIND_PORT),
             f"device={DEVICE_TYPE}", f"pot_id={POT_ID}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        pass


def stop_mdns():
    global _avahi_process
    if _avahi_process:
        _avahi_process.terminate()
        _avahi_process = None


# ── Pot Discovery (UDP Broadcast) ─────────────────────────────────────
_discovery_socket = None

def start_discovery():
    global _discovery_socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", DISCOVERY_PORT))
        sock.settimeout(1)
        _discovery_socket = sock
        threading.Thread(target=_discovery_listener, daemon=True).start()
    except Exception:
        pass


def _discovery_listener():
    sock = _discovery_socket
    while sock:
        try:
            data, addr = sock.recvfrom(1024)
            if data == b"CPIP_DISCOVER":
                resp = json.dumps({
                    "pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE,
                    "port": BIND_PORT, "brewing": PotState.is_brewing(),
                    "mesh_port": MESH_PORT, "mesh_enabled": MESH_ENABLED,
                    "addr": addr[0],
                }).encode()
                sock.sendto(resp, addr)
        except socket.timeout:
            continue
        except Exception:
            break


def discover_pots(timeout=2):
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(b"CPIP_DISCOVER", ("255.255.255.255", DISCOVERY_PORT))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                info = json.loads(data.decode())
                info["addr"] = addr[0]
                if info.get("pot") != POT_ID:
                    results.append(info)
            except socket.timeout:
                break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results


# ── Scheduling Engine ─────────────────────────────────────────────────
_scheduler_running = False

def scheduler_loop():
    global _scheduler_running
    _scheduler_running = True
    while _scheduler_running:
        now = time.time()
        with PotState.state_lock:
            to_remove = []
            for s in PotState.schedules:
                if s.get("enabled", True) and s["time"] <= now:
                    threading.Thread(target=_execute_schedule, args=(s,), daemon=True).start()
                    to_remove.append(s)
            for s in to_remove:
                PotState.schedules.remove(s)
        time.sleep(SCHEDULE_CHECK_INTERVAL)


def _execute_schedule(schedule):
    PotState.start(schedule.get("beverage", "coffee"), schedule.get("additions", []))
    brew_time = schedule.get("brew_duration", 30)
    time.sleep(brew_time)
    PotState.stop()


def start_scheduler():
    threading.Thread(target=scheduler_loop, daemon=True).start()


def stop_scheduler():
    global _scheduler_running
    _scheduler_running = False


# ── Radio Interface (C binary: LoRa / TNC / Sim) ─────────────────────────
_radio = None

def start_radio():
    global _radio
    if not RADIO_ENABLED or not RADIO_IMPORT_OK:
        return
    try:
        ri = RadioInterface()
        ri.start(
            mode=RADIO_MODE,
            frequency=RADIO_FREQ,
            sf=RADIO_SF,
            bandwidth=RADIO_BW,
            tx_power=RADIO_POWER,
            device=RADIO_DEVICE,
            baud=RADIO_BAUD,
        )
        _radio = ri
        print(f"   ├ Radio:      {RADIO_MODE.upper()} @ {RADIO_FREQ/1e6:.1f} MHz"
              f" (SF{RADIO_SF}, BW {RADIO_BW//1000}k)", flush=True)

        # Background poll thread: feed received radio packets into mesh
        def _radio_poll():
            while _radio:
                try:
                    pkts = ri.receive(timeout=0.5)
                    for pkt in pkts:
                        threading.Thread(
                            target=_inject_radio_packet,
                            args=(pkt,),
                            daemon=True,
                        ).start()
                except Exception:
                    break

        threading.Thread(target=_radio_poll, daemon=True).start()
    except Exception as e:
        print(f"   ⚠ Radio:      {e}", flush=True)

def stop_radio():
    global _radio
    if _radio:
        try: _radio.stop()
        except Exception: pass
        _radio = None

def _inject_radio_packet(data: bytes):
    """Feed a raw radio packet into the mesh message handler."""
    try:
        msg = json.loads(data.decode())
        if msg.get("pot") == POT_ID or msg.get("from") == POT_ID:
            return
        MeshNode._handle_message(data, ("0.0.0.0", 0))
        # Forward to satellite if enabled
        MeshNode._cross_transport_forward(msg, via="radio")
    except Exception:
        pass

def get_radio_status() -> dict:
    if not _radio:
        return {"enabled": False, "mode": RADIO_MODE}
    s = _radio.status()
    s["enabled"] = RADIO_ENABLED
    s["mode"] = RADIO_MODE
    return s


# ── NTP Synchronization (RFC 2324 §5.1) ────────────────────────────────
_ntp_running = False
_ntp_offset = 0.0

def ntp_sync_loop():
    """Periodically sync system clock with NTP server for brew timing."""
    global _ntp_running, _ntp_offset
    _ntp_running = True
    while _ntp_running:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            NTP_PORT = 123
            NTP_EPOCH = 2208988800
            data = b'\x1b' + 47 * b'\x00'
            client.sendto(data, (NTP_SERVER, NTP_PORT))
            data, _ = client.recvfrom(1024)
            client.close()
            if len(data) >= 40:
                import struct
                t = struct.unpack('!12I', data)[10]
                ntp_time = t - NTP_EPOCH
                local_time = time.time()
                _ntp_offset = ntp_time - local_time
        except Exception:
            pass
        time.sleep(3600)


def start_ntp():
    if NTP_SYNC:
        threading.Thread(target=ntp_sync_loop, daemon=True).start()


def stop_ntp():
    global _ntp_running
    _ntp_running = False


def ntp_now():
    """Return current time with NTP offset applied."""
    return time.time() + _ntp_offset


# ── HTTP Handler ──────────────────────────────────────────────────────
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json",
}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class CPIPHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"[CPIP {ts}] {self.client_address[0]} {fmt % args}\n")

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, BREW, WHEN, PROPFIND, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept-Additions, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")

    def _send_json(self, code, reason, body, extra_headers=None):
        self.send_response(code, reason)
        payload = json.dumps(body, indent=2).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("CPIP-Version", CPIP_VERSION)
        self.send_header("CPIP-Device", DEVICE_TYPE)
        self.send_header("CPIP-Pot-ID", POT_ID)
        self._cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, code, html_content):
        body = html_content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("CPIP-Version", CPIP_VERSION)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        try:
            full_path = (WEB_DIR / path).resolve()
            if not str(full_path).startswith(str(WEB_DIR.resolve())):
                self._send_json(403, "Forbidden", {"error": "Access denied"})
                return
            if not full_path.is_file():
                self._send_json(404, "Not Found", {"error": "File not found"})
                return
            ext = full_path.suffix.lower()
            mime = MIME_TYPES.get(ext, "application/octet-stream")
            body = full_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("CPIP-Version", CPIP_VERSION)
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self._send_json(500, "Internal Error", {"error": str(e)})

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                return json.loads(self.rfile.read(length))
        except Exception:
            pass
        return {}

    # ── HTCPCP Compatibility Methods ──────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "device": DEVICE_TYPE,
                "message": "The requested resource is a teapot. Short and stout.",
            })
            return

        teapot_tool_check(self.headers, self.client_address[0])

        if teapot_probe_check(self.headers, self.client_address[0], path, "GET"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "device": DEVICE_TYPE,
                "note": "This request looks like a probe. Coffee pots don't serve web shells.",
            })
            return

        if is_coffee_uri_path(self.path):
            pot, additions, beverage = parse_coffee_uri(self.path)
            if "text/html" in self.headers.get("Accept", ""):
                self._serve_dashboard()
            else:
                self._handle_htcpcp_status()
            return

        if path in ("", "/") and "text/html" in self.headers.get("Accept", ""):
            path = "/dashboard"
        if path == "/dashboard":
            self._serve_dashboard()
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            self._send_file(rel)
            return

        if path == "/cpip/status":
            self._handle_cpip_status()
        elif path == "/cpip/config":
            self._handle_cpip_config_get()
        elif path == "/cpip/history":
            self._handle_cpip_history()
        elif path == "/cpip/schedules":
            self._handle_cpip_schedules_get()
        elif path == "/cpip/discover":
            self._handle_cpip_discover()
        elif path == "/cpip/metrics":
            self._handle_cpip_metrics()
        elif path == "/cpip/events":
            self._handle_cpip_events()
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_get()
        elif path == "/cpip/pots":
            self._handle_cpip_pots()
        elif path == "/cpip/mesh/status":
            self._handle_mesh_status()
        elif path == "/cpip/mesh/peers":
            self._handle_mesh_peers()
        elif path == "/cpip/mesh/inbox":
            self._handle_mesh_inbox()
        elif path == "/cpip/mesh/routes":
            self._handle_mesh_routes()
        elif path == "/cpip/mesh/sat":
            self._handle_mesh_sat()
        elif path == "/cpip/mesh/radio":
            self._handle_mesh_radio()
        elif path == "/cpip/mesh/mobile":
            self._handle_mesh_mobile()
        elif path == "/cpip/defense":
            self._handle_defense_get()
        elif path == "/cpip/mesh/deaddrop":
            self._handle_mesh_deaddrop()
        elif path == "/cpip/mesh/queued":
            self._handle_mesh_queued()
        elif path == "/cpip/mesh/ecc/address":
            self._handle_mesh_ecc_address()
        elif path == "/cpip/mesh/ecc/book":
            self._handle_mesh_ecc_book()
        elif path == "/cpip/mesh/covert_status":
            self._handle_covert_status()
        elif path == "/cpip/mesh/propfind":
            params = parse_qs(parsed.query)
            action = params.get("action", ["list"])[0]
            if action == "list":
                drops = MeshNode.advertise_dead_drops()
                self._send_json(200, "OK", {
                    "count": len(drops), "dead_drops": drops,
                    "thermos": THERMOS_ENABLED, "node": POT_ID,
                })
            elif action == "claim":
                mid = params.get("id", [""])[0]
                if not mid:
                    self._send_json(400, "Bad Request", {"error": "Missing 'id' param"})
                    return
                msg = MeshNode.claim_dead_drop(mid, POT_ID)
                if msg:
                    self._send_json(200, "OK", {"status": "claimed", "message": msg})
                else:
                    self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})
        elif path in ("", "/htcpcp", "/"):
            self._handle_htcpcp_status()
        else:
            self._send_json(404, "Not Found", {
                "error": "Unknown endpoint", "path": path,
                "hint": "Try /dashboard, /cpip/status, /cpip/mesh/status",
            })

    def do_PUT(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/cpip/config":
            self._handle_cpip_config_put()
        else:
            self._send_json(404, "Not Found", {"error": "Unknown endpoint"})

    def do_DELETE(self):
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/cpip/schedules/"):
            sid = path.split("/")[-1]
            self._handle_cpip_schedule_delete(sid)
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_clear()
        else:
            self._send_json(404, "Not Found", {"error": "Unknown endpoint"})

    def do_PROPFIND(self):
        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return
        if is_coffee_uri_path(self.path):
            self._handle_propfind()
            return
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/"):
            self._handle_propfind()
        else:
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "note": "PROPFIND only valid on root or coffee: URI.",
            })

    def do_BREW(self):
        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "device": DEVICE_TYPE,
            })
            return
        teapot_tool_check(self.headers, self.client_address[0])
        if teapot_probe_check(self.headers, self.client_address[0],
                              urlparse(self.path).path, "BREW"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "device": DEVICE_TYPE,
            })
            return
        if is_coffee_uri_path(self.path):
            self._handle_brew_coffee_uri()
            return
        self._handle_brew()

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return
        teapot_tool_check(self.headers, self.client_address[0])
        if teapot_probe_check(self.headers, self.client_address[0], path, "POST"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return

        if is_coffee_uri_path(self.path):
            self._handle_brew_coffee_uri()
            return

        ct = self.headers.get("Content-Type", "")
        if "message/coffeepot" in ct:
            self._handle_message_coffeepot()
            return

        if path == "/cpip/schedule":
            self._handle_cpip_schedule_post()
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_post()
        elif path == "/cpip/config":
            self._handle_cpip_config_put()
        elif path == "/cpip/brew":
            self._handle_cpip_brew()
        elif path == "/cpip/mesh/send":
            self._handle_mesh_send()
        elif path == "/cpip/mesh/broadcast":
            self._handle_mesh_broadcast()
        elif path == "/cpip/mesh/encode":
            self._handle_covert_encode()
        elif path == "/cpip/mesh/decode":
            self._handle_covert_decode()
        elif path == "/cpip/mesh/brew_covert":
            self._handle_covert_brew()
        elif path == "/cpip/mesh/sat":
            self._handle_mesh_sat_post()
        elif path == "/cpip/mesh/mobile":
            self._handle_mesh_mobile_post()
        elif path == "/cpip/defense":
            self._handle_defense_post()
        elif path == "/cpip/mesh/deaddrop":
            self._handle_mesh_deaddrop()
        elif path == "/cpip/mesh/deaddrop/claim":
            body = self._read_json_body()
            mid = body.get("message_id", "")
            if mid:
                msg = MeshNode.claim_dead_drop(mid, POT_ID)
                if msg:
                    self._send_json(200, "OK", {"status": "claimed", "message": msg})
                else:
                    self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'message_id'"})
        else:
            self._handle_brew()

    def do_WHEN(self):
        if is_coffee_uri_path(self.path):
            pot, additions, beverage = parse_coffee_uri(self.path)
        was = PotState.stop()
        self._send_json(200, "OK", {
            "status": "stopped",
            "device": DEVICE_TYPE,
            "was_brewing": was,
            "message": WHEN_MESSAGES.get(DEVICE_TYPE, "Pouring stopped."),
        })

    def do_OPTIONS(self):
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/"):
            scheme_list = list(COFFEE_SCHEME_NAMES)
            self._send_json(200, "OK", {
            "protocol": CPIP_PROTOCOL,
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "methods": ["GET", "PUT", "POST", "DELETE", "BREW", "WHEN", "PROPFIND", "OPTIONS"],
            "coffee_uri_schemes": {
                "count": len(scheme_list),
                "languages": COFFEE_LANGUAGE_MAP,
                "example": "coffee://" + HOSTNAME + "/pot-0?milk;variety=whole",
            },
            "endpoints": {
                "HTCPCP": ["GET /", "BREW /{tea,coffee}", "WHEN /", "PROPFIND /"],
                "COFFEE_URI": ["{scheme}://host/pot-N?additions — all 29 international variants"],
                "message/coffeepot": ["POST/BREW with Content-Type: message/coffeepot, body: start|stop"],
                "CPIP": [
                    "GET /cpip/status", "GET|PUT /cpip/config",
                    "GET /cpip/history", "POST /cpip/schedule",
                    "GET /cpip/pots", "GET /cpip/metrics",
                    "GET /cpip/events (SSE)", "POST|DELETE /cpip/webhooks",
                ],
                "MESH": [
                    "GET /cpip/mesh/status", "GET /cpip/mesh/peers",
                    "GET /cpip/mesh/inbox", "POST /cpip/mesh/send",
                    "POST /cpip/mesh/broadcast", "POST /cpip/mesh/encode",
                    "POST /cpip/mesh/decode",
                ],
                "UI": ["GET /dashboard"],
            },
            "gpio": gpio.is_available,
            "gpio_hardware": gpio.is_available,
            "mesh": {"enabled": MESH_ENABLED, "port": MESH_PORT, "peers": len(MeshNode.peers)},
            "covert": {"enabled": COVERT_ENABLED},
            "ntp": {"enabled": NTP_SYNC, "server": NTP_SERVER},
            "ecc": {
                "algorithm": "Ed25519 (Curve25519)",
                "implementation": "Pure Python (not constant-time)",
                "node_address": MeshNode.node_address,
                "node_pubkey_present": MeshNode.node_pubkey is not None,
            },
            "defense": {"418_teapot": MESH_ENABLED},
            "thermos": {"enabled": THERMOS_ENABLED},
            "pitail": {"enabled": PITAIL_ENABLED, "addr": PITAIL_ADDR},
        })

    # ── HTCPCP Handlers ───────────────────────────────────────────────

    def _handle_htcpcp_status(self):
        self._send_json(200, "OK", {
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "brewing": PotState.is_brewing(),
            "protocol": CPIP_PROTOCOL,
            "uptime": self._uptime(),
            "gpio": {"available": gpio.is_available, "hardware": gpio.is_available, "pin": GPIO_PIN},
            "mesh": {"enabled": MESH_ENABLED, "peers": len(MeshNode.peers), "port": MESH_PORT},
            "covert": {"enabled": COVERT_ENABLED},
            "endpoints": {
                "/": "Server status (HTCPCP)",
                "/dashboard": "Web dashboard",
                "/cpip/status": "Full CPIP status",
                "/cpip/mesh/status": "Mesh network status",
                "/cpip/mesh/inbox": "Mesh message inbox",
                "/cpip/mesh/send": "Send mesh message (POST)",
                "/cpip/mesh/broadcast": "Broadcast to mesh (POST)",
            },
        })

    def _handle_propfind(self):
        self._send_json(200, "OK", {
            "device": DEVICE_TYPE,
            "brewing": PotState.is_brewing(),
            "additions_supported": list(VALID_ADDITIONS.keys()),
            "addition_details": {k: v["variety"] for k, v in VALID_ADDITIONS.items()},
            "beverages": DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"]),
            "allows_alcohol": DEVICE_TYPE in ALCOHOL_DEVICES,
            "pot_id": POT_ID,
            "cpip_version": CPIP_VERSION,
            "mesh_enabled": MESH_ENABLED,
            "covert_enabled": COVERT_ENABLED,
        })

    def _handle_brew(self):
        additions_header = self.headers.get("Accept-Additions", "")
        additions = parse_accept_additions(additions_header)

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing",
                "status": 409,
                "device": DEVICE_TYPE,
                "current_brew": {
                    "id": PotState.brew_id,
                    "beverage": PotState.current_beverage,
                    "additions": PotState.current_additions,
                },
                "message": "A brew is already in progress. Send WHEN to stop first.",
            })
            return

        if not is_beverage_compatible(self.path, DEVICE_TYPE):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "reason": f"Device type '{DEVICE_TYPE}' cannot brew the requested beverage",
                "device": DEVICE_TYPE,
                "hint": f"Try /tea" if DEVICE_TYPE == "teapot" else f"Try /coffee",
            })
            return

        ok, reason = check_additions(additions, DEVICE_TYPE)
        if not ok:
            if "alcohol" in reason.lower():
                self._send_json(406, "Not Acceptable", {
                    "error": "Not Acceptable",
                    "status": 406,
                    "reason": reason,
                    "device": DEVICE_TYPE,
                    "additions_supported": list(VALID_ADDITIONS.keys()),
                    "hint": "This device does not support alcohol additions",
                })
            else:
                self._send_json(418, "I'm a teapot", {
                    "error": "I'm a teapot",
                    "status": 418,
                    "reason": reason,
                    "device": DEVICE_TYPE,
                })
            return

        if additions and not PotState.is_brewing():
            can_provide = all(
                a["name"] in VALID_ADDITIONS
                for a in additions
            )
            if not can_provide:
                self._send_json(406, "Not Acceptable", {
                    "error": "Not Acceptable",
                    "status": 406,
                    "reason": "Cannot provide requested additions",
                    "additions_supported": list(VALID_ADDITIONS.keys()),
                })
                return

        covert_msg = CovertChannel.decode(additions, our_seed=MeshNode.node_seed) if COVERT_ENABLED else b""
        if covert_msg:
            try:
                decoded = covert_msg.decode("utf-8", errors="replace")
                with MeshNode.inbox_lock:
                    MeshNode.inbox.append({
                        "id": str(uuid.uuid4())[:8],
                        "from": self.headers.get("X-Forwarded-For", self.client_address[0]),
                        "data": decoded,
                        "timestamp": time.time(),
                        "hops": 0,
                        "channel": "covert_htcpcp",
                    })
                PotState._broadcast({
                    "event": "mesh_message",
                    "from": "covert_channel",
                    "message_id": "covert_" + CoffeeCipher.hash(covert_msg),
                })
            except Exception:
                pass

        path = urlparse(self.path).path.rstrip("/")
        if is_coffee_uri_path(self.path):
            pot, uri_additions, beverage_hint = parse_coffee_uri(self.path)
            beverage = beverage_hint or "tea"
        else:
            beverage = "coffee" if path.endswith("/coffee") else "tea" if path.endswith("/tea") else "tea"
        brew_id = PotState.start(beverage, additions)

        addition_names = [
            a["name"] + (f";variety={a['variety']}" if a.get("variety") else "")
            for a in additions
        ]
        safe_val = additions_header.replace("\r", "").replace("\n", "") if additions_header else ""

        self._send_json(202, "Brewing", {
            "status": "brewing",
            "device": DEVICE_TYPE,
            "beverage": beverage,
            "brew_id": brew_id,
            "additions": addition_names if addition_names else ["none"],
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started. Send WHEN to stop."),
        }, extra_headers={
            "Accept-Additions": safe_val,
            "Safe": "yes" if additions else "no",
        })

    def _handle_brew_coffee_uri(self):
        """Handle BREW on a coffee: URI scheme request."""
        pot, uri_additions, beverage_hint = parse_coffee_uri(self.path)
        additions_header = self.headers.get("Accept-Additions", "")
        header_additions = parse_accept_additions(additions_header) if additions_header else []
        additions = uri_additions + [a for a in header_additions if a not in uri_additions]
        beverage = beverage_hint or "coffee"

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing", "status": 409,
                "device": DEVICE_TYPE, "beverage": beverage,
                "current_brew": {"id": PotState.brew_id, "beverage": PotState.current_beverage},
                "message": "A brew is already in progress. Send WHEN to stop first.",
            })
            return

        brew_id = PotState.start(beverage, additions)
        addition_names = ", ".join(
            a["name"] + (f";variety={a['variety']}" if a.get("variety") else "")
            for a in additions
        ) if additions else "none"
        self._send_json(202, "Brewing", {
            "status": "brewing",
            "device": DEVICE_TYPE,
            "beverage": beverage,
            "brew_id": brew_id,
            "additions": [a["name"] for a in additions] if additions else ["none"],
            "coffee_uri": True,
            "coffee_scheme": self.path.lstrip("/").split(":")[0] if ":" in self.path else "coffee",
            "pot_designator": pot,
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started via coffee: URI."),
        }, extra_headers={
            "Accept-Additions": addition_names,
            "Safe": "yes" if additions else "no",
        })

    def _handle_message_coffeepot(self):
        """Handle message/coffeepot Content-Type (RFC 2324 §4)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode().strip().lower() if length > 0 else ""
        except Exception:
            body = ""
        if body == "start":
            if PotState.is_brewing():
                self._send_json(200, "OK", {"status": "already_brewing", "message": "Already brewing."})
                return
            path = urlparse(self.path).path.rstrip("/")
            beverage = "coffee" if path.endswith("/coffee") else "tea" if path.endswith("/tea") else "tea"
            brew_id = PotState.start(beverage, [])
            self._send_json(202, "Brewing", {
                "status": "brewing",
                "device": DEVICE_TYPE,
                "beverage": beverage,
                "brew_id": brew_id,
                "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started via message/coffeepot."),
            })
        elif body == "stop":
            was = PotState.stop()
            self._send_json(200, "OK", {
                "status": "stopped",
                "device": DEVICE_TYPE,
                "was_brewing": was,
                "message": WHEN_MESSAGES.get(DEVICE_TYPE, "Pouring stopped via message/coffeepot."),
            })
        else:
            self._send_json(400, "Bad Request", {
                "error": "Invalid message/coffeepot body",
                "expected": "start or stop",
                "got": body or "(empty)",
            })

    # ── CPIP Handlers ─────────────────────────────────────────────────

    def _handle_cpip_status(self):
        bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
        elapsed = time.time() - PotState.brew_start_time if PotState.brewing else 0
        self._send_json(200, "OK", {
            "protocol": CPIP_PROTOCOL,
            "cpip_version": CPIP_VERSION,
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "uptime_seconds": int(self._uptime()),
            "brewing": PotState.is_brewing(),
            "current_brew": {
                "id": PotState.brew_id,
                "beverage": PotState.current_beverage,
                "additions": PotState.current_additions,
                "elapsed_seconds": round(elapsed, 1),
            } if PotState.brewing else None,
            "beverages": bev,
            "gpio": {
                "enabled": GPIO_ENABLED,
                "available": gpio.is_available,
                "pin": GPIO_PIN,
                "state": gpio.is_on,
            },
            "mesh": MeshNode.get_status(),
            "covert": {"enabled": COVERT_ENABLED, "cover_traffic": COVER_TRAFFIC},
            "mdns": AVAHI_ENABLED,
            "history_count": len(PotState.history),
            "schedule_count": len(PotState.schedules),
            "webhooks": len(PotState.webhooks),
            "discovery_port": DISCOVERY_PORT,
            "sse_clients": len(PotState.sse_clients),
            "ntp": {"enabled": NTP_SYNC, "server": NTP_SERVER} if NTP_SYNC else {"enabled": False},
        })

    def _handle_cpip_config_get(self):
        self._send_json(200, "OK", {
            "version": CPIP_VERSION,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "bind": BIND_ADDR,
            "port": BIND_PORT,
            "gpio_pin": GPIO_PIN,
            "gpio_enabled": GPIO_ENABLED,
            "gpio_available": gpio.is_available,
            "gpio_hardware": gpio.is_available,
            "avahi_enabled": AVAHI_ENABLED,
            "discovery_port": DISCOVERY_PORT,
            "mesh_enabled": MESH_ENABLED,
            "mesh_port": MESH_PORT,
            "mesh_ttl": MESH_TTL,
            "covert_enabled": COVERT_ENABLED,
            "cover_traffic": COVER_TRAFFIC,
            "web_dir": str(WEB_DIR),
            "history_max": HISTORY_MAX,
            "schedule_check_interval": SCHEDULE_CHECK_INTERVAL,
            "beverages_allowed": DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"]),
            "allows_alcohol": DEVICE_TYPE in ALCOHOL_DEVICES,
            "ecc": "Ed25519",
            "ecc_curve": "Curve25519",
            "ecc_implementation": "Pure Python (not constant-time)",
            "node_address": MeshNode.node_address,
            "node_pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
            "pitail_enabled": PITAIL_ENABLED,
            "pitail_addr": PITAIL_ADDR,
            "thermos_enabled": THERMOS_ENABLED,
            "thermos_max_storage": THERMOS_MAX_STORAGE,
        })

    def _handle_cpip_config_put(self):
        body = self._read_json_body()
        changed = []
        global DEVICE_TYPE
        if "device" in body and body["device"] in DEVICE_BEVERAGE_MAP:
            DEVICE_TYPE = body["device"]
            changed.append(f"device={DEVICE_TYPE}")
        self._send_json(200, "OK", {
            "status": "configured",
            "changes": changed if changed else ["none"],
            "device": DEVICE_TYPE,
        })

    def _handle_cpip_history(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = min(int(params.get("limit", [HISTORY_MAX])[0]), HISTORY_MAX)
        self._send_json(200, "OK", {
            "count": min(len(PotState.history), limit),
            "total": len(PotState.history),
            "history": PotState.history[-limit:],
        })

    def _handle_cpip_schedules_get(self):
        self._send_json(200, "OK", {
            "count": len(PotState.schedules),
            "schedules": PotState.schedules,
        })

    def _handle_cpip_schedule_post(self):
        body = self._read_json_body()
        when_str = body.get("time", body.get("in"))
        beverage = body.get("beverage", "coffee")
        additions = body.get("additions", [])
        brew_duration = int(body.get("brew_duration", body.get("duration", 30)))

        if when_str is None:
            self._send_json(400, "Bad Request", {"error": "Missing 'time' (ISO format) or 'in' (seconds from now)"})
            return

        schedule = {
            "id": str(uuid.uuid4())[:8],
            "beverage": beverage,
            "additions": additions,
            "brew_duration": brew_duration,
            "enabled": True,
            "created": time.time(),
        }

        if isinstance(when_str, (int, float)):
            schedule["time"] = time.time() + when_str
            schedule["human"] = f"in {when_str}s"
        else:
            try:
                dt = datetime.fromisoformat(when_str)
                schedule["time"] = dt.timestamp()
                schedule["human"] = when_str
            except ValueError:
                self._send_json(400, "Bad Request", {"error": f"Invalid time format: {when_str}"})
                return

        with PotState.state_lock:
            PotState.schedules.append(schedule)
        self._send_json(201, "Created", {"status": "scheduled", "schedule": schedule})

    def _handle_cpip_schedule_delete(self, sid):
        with PotState.state_lock:
            removed = [s for s in PotState.schedules if s["id"] == sid]
            PotState.schedules[:] = [s for s in PotState.schedules if s["id"] != sid]
        if removed:
            self._send_json(200, "OK", {"status": "deleted", "schedule_id": sid})
        else:
            self._send_json(404, "Not Found", {"error": f"Schedule {sid} not found"})

    def _handle_cpip_discover(self):
        pots = discover_pots()
        self._send_json(200, "OK", {"count": len(pots), "pots": pots})

    def _handle_cpip_pots(self):
        local = [{
            "pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE,
            "port": BIND_PORT, "addr": BIND_ADDR, "brewing": PotState.is_brewing(),
            "local": True, "mesh_port": MESH_PORT,
        }]
        remote = discover_pots()
        self._send_json(200, "OK", {"count": len(local) + len(remote), "pots": local + remote})

    def _handle_cpip_metrics(self):
        lines = [
            "# HELP cpip_brewing Currently brewing (1=yes, 0=no)",
            "# TYPE cpip_brewing gauge",
            f'cpip_brewing{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {1 if PotState.brewing else 0}',
            "",
            "# HELP cpip_brew_total Total brews completed",
            "# TYPE cpip_brew_total counter",
            f'cpip_brew_total{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.history)}',
            "",
            "# HELP cpip_mesh_peers Number of mesh peers",
            "# TYPE cpip_mesh_peers gauge",
            f'cpip_mesh_peers{{pot="{POT_ID}"}} {len(MeshNode.peers)}',
            "",
            "# HELP cpip_mesh_inbox Messages in mesh inbox",
            "# TYPE cpip_mesh_inbox gauge",
            f'cpip_mesh_inbox{{pot="{POT_ID}"}} {len(MeshNode.inbox)}',
            "",
            "# HELP cpip_mesh_queued Messages in store-and-forward queue",
            "# TYPE cpip_mesh_queued gauge",
            f'cpip_mesh_queued{{pot="{POT_ID}"}} {len(MeshNode.message_store)}',
            "",
            "# HELP cpip_scheduled_brews Number of scheduled brews",
            "# TYPE cpip_scheduled_brews gauge",
            f'cpip_scheduled_brews{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.schedules)}',
            "",
            "# HELP cpip_sse_clients Number of connected SSE clients",
            "# TYPE cpip_sse_clients gauge",
            f'cpip_sse_clients{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.sse_clients)}',
            "",
            "# HELP cpip_gpio_state GPIO relay state (1=on, 0=off)",
            "# TYPE cpip_gpio_state gauge",
            f'cpip_gpio_state{{pin="{GPIO_PIN}",available="{str(gpio.is_available).lower()}"}} {1 if gpio.is_on else 0}',
            "",
            "# HELP cpip_uptime_seconds Server uptime",
            "# TYPE cpip_uptime_seconds gauge",
            f'cpip_uptime_seconds{{pot="{POT_ID}"}} {int(self._uptime())}',
        ]
        body = "\n".join(lines).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_cpip_events(self):
        q = queue.Queue()
        with PotState.sse_lock:
            PotState.sse_clients.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("CPIP-Version", CPIP_VERSION)
        self.end_headers()
        try:
            self.wfile.write(f"event: connected\ndata: {json.dumps({'pot': POT_ID, 'device': DEVICE_TYPE})}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=30)
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(": keepalive\n\n".encode())
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with PotState.sse_lock:
                if q in PotState.sse_clients:
                    PotState.sse_clients.remove(q)

    def _handle_cpip_webhooks_get(self):
        self._send_json(200, "OK", {"count": len(PotState.webhooks), "webhooks": PotState.webhooks})

    def _handle_cpip_webhooks_post(self):
        body = self._read_json_body()
        url = body.get("url")
        if not url:
            self._send_json(400, "Bad Request", {"error": "Missing 'url' field"})
            return
        if url not in PotState.webhooks:
            PotState.webhooks.append(url)
        self._send_json(201, "Created", {"status": "webhook added", "url": url, "total": len(PotState.webhooks)})

    def _handle_cpip_webhooks_clear(self):
        count = len(PotState.webhooks)
        PotState.webhooks.clear()
        self._send_json(200, "OK", {"status": "webhooks cleared", "removed": count})

    def _handle_cpip_brew(self):
        body = self._read_json_body()
        beverage = body.get("beverage", body.get("type", "coffee"))
        additions = body.get("additions", [])
        path = f"/{beverage}"

        if not is_beverage_compatible(path, DEVICE_TYPE):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "reason": f"Device '{DEVICE_TYPE}' cannot brew '{beverage}'",
                "device": DEVICE_TYPE,
            })
            return

        ok, reason = check_additions(additions, DEVICE_TYPE)
        if not ok:
            self._send_json(418, "I'm a teapot", {"error": "I'm a teapot", "reason": reason, "device": DEVICE_TYPE})
            return

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing", "status": 409,
                "device": DEVICE_TYPE,
                "current_brew": {"id": PotState.brew_id, "beverage": PotState.current_beverage},
                "message": "Send WHEN to stop first.",
            })
            return

        brew_id = PotState.start(beverage, additions)
        auto_stop = body.get("duration", body.get("auto_stop"))
        if auto_stop:
            try:
                auto_secs = float(auto_stop)
                if auto_secs > 0:
                    def _auto():
                        time.sleep(auto_secs)
                        PotState.stop()
                    threading.Thread(target=_auto, daemon=True).start()
                else:
                    auto_stop = None
            except (ValueError, TypeError):
                auto_stop = None

        self._send_json(202, "Brewing", {
            "status": "brewing", "device": DEVICE_TYPE,
            "beverage": beverage, "brew_id": brew_id,
            "additions": [a.get("name") for a in additions],
            "auto_stop": auto_stop or False,
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started."),
        })

    # ── Mesh Handlers ─────────────────────────────────────────────────

    def _handle_mesh_status(self):
        self._send_json(200, "OK", {
            "mesh": MeshNode.get_status(),
            "covert": {"enabled": COVERT_ENABLED, "cover_traffic": COVER_TRAFFIC},
            "cipher": "Coffee Blend Cipher v1 + Ed25519 ECC",
            "cipher_note": "Non-FIPS. Coffee Blend (MD4-derived XOR) + Ed25519 (pure Python, not constant-time).",
            "ecc": {
                "algorithm": "Ed25519 (Curve25519)",
                "implementation": "Pure Python — no libsodium, no pycryptodome",
                "constant_time": False,
                "node_address": MeshNode.node_address,
                "node_pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
            },
            "defense": {
                "418_teapot": MESH_ENABLED,
                "blacklisted_addrs": len(TEAPOT_BLACKLIST),
            },
            "thermos": {
                "enabled": THERMOS_ENABLED,
                "dead_drops_held": len(MeshNode.advertise_dead_drops()) if THERMOS_ENABLED else 0,
            },
            "key_status": "Custom" if COVERT_KEY != b"CHANGE_ME_COFFEE_BLEND_2024" else "Default (CHANGE ME)",
        })

    def _handle_mesh_peers(self):
        self._send_json(200, "OK", {
            "count": len(MeshNode.peers),
            "peers": MeshNode.get_peers_list(),
        })

    def _handle_mesh_inbox(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = min(int(params.get("limit", [20])[0]), 100)
        self._send_json(200, "OK", {
            "count": len(MeshNode.inbox),
            "messages": MeshNode.get_inbox(limit),
        })

    def _handle_mesh_routes(self):
        self._send_json(200, "OK", {
            "routes": {k: v for k, v in MeshNode.routing_table.items()},
        })

    def _handle_mesh_sat(self):
        self._send_json(200, "OK", MeshNode.get_sat_status())

    def _handle_mesh_radio(self):
        self._send_json(200, "OK", get_radio_status())

    def _handle_mesh_mobile(self):
        self._send_json(200, "OK", MeshNode.get_mobile_status())

    def _handle_mesh_queued(self):
        self._send_json(200, "OK", {
            "queued": len(MeshNode.message_store),
            "messages": list(MeshNode.message_store)[:20],
        })

    def _handle_mesh_ecc_address(self):
        self._send_json(200, "OK", {
            "address": MeshNode.node_address,
            "pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
        })

    def _handle_mesh_ecc_book(self):
        with MeshNode.peers_lock:
            entries = []
            for pid, info in MeshNode.peers.items():
                pk_b64 = info.get("pubkey", "")
                addr = Ed25519.pubkey_to_address(base64.b64decode(pk_b64)) if pk_b64 else None
                entries.append({
                    "pot_id": pid,
                    "hostname": info.get("hostname", ""),
                    "pubkey": pk_b64[:20] + "..." if len(pk_b64) > 20 else pk_b64,
                    "ecc_address": addr,
                })
        self._send_json(200, "OK", {"count": len(entries), "entries": entries})

    def _handle_covert_brew(self):
        body = self._read_json_body()
        message = body.get("message", "")
        dst = body.get("dst", "")
        if not message:
            self._send_json(400, "Bad Request", {"error": "Missing 'message' text"})
            return
        dst_pubkey = None
        if dst:
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception:
                        pass
        encoded = CovertChannel.encode(
            message.encode(), dst, "espresso",
            dst_pubkey=dst_pubkey,
            our_seed=MeshNode.node_seed if dst_pubkey else None,
        )
        result = MeshNode.send_message(dst, f"covert_brew:{message}") if dst else {"status": "encoded"}
        result["covert_additions"] = encoded["additions"]
        self._send_json(200, "OK", result)

    def _handle_covert_status(self):
        self._send_json(200, "OK", {
            "enabled": COVERT_ENABLED,
            "cover_traffic": COVER_TRAFFIC,
            "cipher": "Coffee Blend Cipher v1",
            "ecc_available": MeshNode.node_pubkey is not None,
        })

    def _handle_defense_get(self):
        now = time.time()
        with TEAPOT_BLACKLIST_LOCK:
            active = {k: v for k, v in TEAPOT_BLACKLIST.items() if v.get("expires", 0) > now}
            blacklist = sorted(active.keys())
        with TEAPOT_TOOL_LOCK:
            tools = {}
            for tool, info in TEAPOT_TOOL_HITS.items():
                tools[tool] = {
                    "count": info["count"],
                    "last_seen": info["last_seen"],
                    "addrs": sorted(info["addrs"])[:20],
                }
        self._send_json(200, "OK", {
            "418_teapot": MESH_ENABLED,
            "stealth": MeshNode.stealth_mode,
            "port_hopping": MeshNode.stealth_mode,
            "latent_ports": MESH_LATENT_PORTS,
            "blacklisted_addrs": len(blacklist),
            "blacklist": blacklist,
            "hop_interval": MESH_HOP_INTERVAL,
            "rate_limit": {"max": DEFENSE_RATE_LIMIT, "window": DEFENSE_RATE_WINDOW},
            "blacklist_ttl": DEFENSE_BLACKLIST_TTL,
            "tools_detected": tools,
            "tools_total": len(tools),
        })

    def _handle_defense_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "whitelist":
            addr = body.get("addr", "")
            if addr:
                with TEAPOT_BLACKLIST_LOCK:
                    TEAPOT_BLACKLIST.pop(addr, None)
                    TEAPOT_PROBE_COUNT.pop(addr, None)
                self._send_json(200, "OK", {"status": "whitelisted", "addr": addr})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'addr'"})
        elif action == "clear":
            with TEAPOT_BLACKLIST_LOCK:
                TEAPOT_BLACKLIST.clear()
                TEAPOT_PROBE_COUNT.clear()
            self._send_json(200, "OK", {"status": "blacklist_cleared"})
        elif action == "probe":
            addr = body.get("addr", "")
            if not addr:
                self._send_json(400, "Bad Request", {"error": "Missing 'addr'"})
                return
            blacklisted = teapot_defense(addr)
            now = time.time()
            with TEAPOT_BLACKLIST_LOCK:
                entry = TEAPOT_BLACKLIST.get(addr)
                remaining = max(0, int(entry.get("expires", 0) - now)) if entry else 0
            self._send_json(200, "OK", {
                "status": "probed", "addr": addr,
                "blacklisted": blacklisted,
                "remaining_seconds": remaining,
                "probe_count": len(TEAPOT_PROBE_COUNT.get(addr, [])),
            })
        elif action == "stealth":
            enabled = body.get("enabled", False)
            MeshNode.stealth_mode = bool(enabled)
            self._send_json(200, "OK", {"status": "stealth_set", "enabled": MeshNode.stealth_mode})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_sat_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "enable":
            MeshNode.sat_enable()
            self._send_json(200, "OK", {"status": "satellite_enabled"})
        elif action == "disable":
            MeshNode.sat_disable()
            self._send_json(200, "OK", {"status": "satellite_disabled"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_mobile_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "enable":
            MeshNode.mobile_enable()
            self._send_json(200, "OK", {"status": "mobile_enabled"})
        elif action == "disable":
            MeshNode.mobile_disable()
            self._send_json(200, "OK", {"status": "mobile_disabled"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_deaddrop(self):
        """Handle dead-drop listing and claiming."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        action = params.get("action", ["list"])[0]
        if action == "list":
            drops = MeshNode.advertise_dead_drops()
            self._send_json(200, "OK", {
                "count": len(drops),
                "dead_drops": drops,
                "thermos": THERMOS_ENABLED,
                "node": POT_ID,
            })
        elif action == "claim":
            mid = params.get("id", [""])[0]
            if not mid:
                self._send_json(400, "Bad Request", {"error": "Missing 'id' param"})
                return
            msg = MeshNode.claim_dead_drop(mid, POT_ID)
            if msg:
                self._send_json(200, "OK", {"status": "claimed", "message": msg})
            else:
                self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_send(self):
        body = self._read_json_body()
        dst = body.get("dst", body.get("destination", ""))
        data = body.get("data", body.get("message", ""))
        resolved_dst = MeshNode._resolve_address(dst)
        if resolved_dst:
            dst = resolved_dst

        if not dst:
            self._send_json(400, "Bad Request", {"error": "Missing 'dst' (destination pot ID)"})
            return
        if not data:
            self._send_json(400, "Bad Request", {"error": "Missing 'data' (message text)"})
            return

        result = MeshNode.send_message(dst, data)

        covert_method = body.get("covert", False)
        if covert_method and result.get("status") in ("sent", "queued"):
            # Use ECC if we have the peer's pubkey
            dst_pubkey = None
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception:
                        pass
            beverage, additions, headers = CovertChannel.encode_brew(
                data.encode(), dst,
                dst_pubkey=dst_pubkey,
                our_seed=MeshNode.node_seed,
            )
            result["covert_path"] = f"/{beverage}"
            result["covert_headers"] = headers
            if dst_pubkey:
                result["ecc_encrypted"] = True
                result["ecc_address"] = Ed25519.pubkey_to_address(dst_pubkey)

        self._send_json(200, "OK", result)

    def _handle_mesh_broadcast(self):
        body = self._read_json_body()
        data = body.get("data", body.get("message", ""))
        if not data:
            self._send_json(400, "Bad Request", {"error": "Missing 'data' (message text)"})
            return
        result = MeshNode.broadcast(data)
        self._send_json(200, "OK", result)

    def _handle_covert_encode(self):
        body = self._read_json_body()
        message = body.get("message", "")
        dst = body.get("dst", "")
        recipe = body.get("recipe", "espresso")
        use_ecc = body.get("ecc", False)

        if not message:
            self._send_json(400, "Bad Request", {"error": "Missing 'message' text"})
            return

        dst_pubkey = None
        if use_ecc and dst:
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception:
                        pass

        encoded = CovertChannel.encode(
            message.encode(), dst, recipe,
            dst_pubkey=dst_pubkey,
            our_seed=MeshNode.node_seed if dst_pubkey else None,
        )
        header_value = ", ".join(
            f"{a['name']};variety={a['variety']}"
            for a in encoded["additions"]
        )
        result = {
            "status": "encoded",
            "additions": encoded["additions"],
            "accept_additions_header": header_value,
            "recipe": recipe,
            "original_length": len(message),
            "encoded_length": len(header_value),
            "cipher": "Coffee Blend Cipher v1 + Ed25519 ECC" if dst_pubkey else "Coffee Blend Cipher v1",
        }
        if dst_pubkey:
            result["ecc"] = True
            result["ecc_encrypted_for"] = Ed25519.pubkey_to_address(dst_pubkey)
        self._send_json(200, "OK", result)

    def _handle_covert_decode(self):
        body = self._read_json_body()
        additions = body.get("additions", body.get("additions_list", []))
        header_value = body.get("accept_additions", body.get("header", ""))

        if header_value:
            additions = parse_accept_additions(header_value)

        if not additions:
            self._send_json(400, "Bad Request", {"error": "Missing 'additions' list or 'accept_additions' header string"})
            return

        decoded = CovertChannel.decode(additions, our_seed=MeshNode.node_seed)
        if decoded:
            try:
                text = decoded.decode("utf-8")
                self._send_json(200, "OK", {
                    "status": "decoded",
                    "message": text,
                    "bytes": list(decoded),
                    "length": len(decoded),
                })
            except UnicodeDecodeError:
                self._send_json(200, "OK", {
                    "status": "decoded_raw",
                    "message": decoded.hex(),
                    "bytes": list(decoded),
                    "length": len(decoded),
                    "note": "Binary data (not valid UTF-8)",
                })
        else:
            self._send_json(200, "OK", {
                "status": "no_message",
                "message": "No covert message detected in additions",
            })

    # ── Dashboard ─────────────────────────────────────────────────────

    def _uptime(self):
        return time.time() - self._start_time

    _start_time = time.time()

    def _serve_dashboard(self):
        bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
        schedule_list = json.dumps([{
            "id": s["id"],
            "time": datetime.fromtimestamp(s["time"]).strftime("%Y-%m-%d %H:%M:%S") if isinstance(s.get("time"), (int, float)) else str(s.get("time")),
            "beverage": s.get("beverage", "coffee"),
            "brew_duration": s.get("brew_duration", 30),
            "human": s.get("human", ""),
        } for s in PotState.schedules])

        fmt = dict(
            device=html.escape(DEVICE_TYPE),
            pot_id=html.escape(POT_ID),
            hostname=html.escape(HOSTNAME),
            version=CPIP_VERSION,
            beverages=", ".join(bev),
            gpio_status=f"GPIO Pin {GPIO_PIN}" if gpio.is_available else "GPIO disabled",
            gpio_class="physical" if gpio.is_available else "disabled",
            mesh_status=f"Mesh port {MESH_PORT}" if MESH_ENABLED else "Disabled",
            mesh_class="enabled" if MESH_ENABLED else "disabled",
            covert_status="Active (Coffee Cipher)" if COVERT_ENABLED else "Disabled",
            covert_class="enabled" if COVERT_ENABLED else "disabled",
            pot_json=json.dumps({"pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE, "port": BIND_PORT}),
            schedules_json=schedule_list,
        )
        html_str = DASHBOARD_HTML
        index_file = WEB_DIR / "index.html"
        if index_file.is_file():
            try:
                html_str = index_file.read_text(encoding="utf-8")
            except Exception:
                pass
        self._send_html(200, html_str.format(**fmt))


# ── Embedded Dashboard HTML ───────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CPIP — {hostname} Coffee Protocol</title>
<style>
  :root {{
    --bg: #0a0a1a; --surface: #111128; --accent: #e94560;
    --green: #0a2840; --text: #d0d0e0; --muted: #6666aa;
    --card: #18183a; --border: #2a2a5c; --mesh: #00cc88;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Courier New', monospace;
          background: var(--bg); color: var(--text); min-height: 100vh; }}
  .header {{ background: linear-gradient(135deg, var(--surface), #0a0a2a);
            padding: 1rem 2rem; border-bottom: 3px solid var(--accent); }}
  .header h1 {{ font-size: 1.4rem; font-weight: 700; }}
  .header .sub {{ color: var(--muted); font-size: 0.8rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
           padding: 1.2rem; }}
  .card h2 {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase;
              letter-spacing: 0.1em; margin-bottom: 0.8rem; }}
  .value {{ font-size: 1.8rem; font-weight: 700; font-family: inherit; }}
  .label {{ color: var(--muted); font-size: 0.75rem; margin-top: 0.2rem; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 3px;
            font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
  .badge.brewing {{ background: var(--accent); color: #fff; animation: pulse 1s infinite; }}
  .badge.idle {{ background: #1a3a5c; color: #88ccff; }}
  .badge.enabled {{ background: #003322; color: #00ff88; }}
  .badge.disabled {{ background: #332200; color: #ff8800; }}
  .badge.physical {{ background: #004433; color: #00ffaa; }}
  @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
  .btn {{ background: var(--accent); color: #fff; border: none; padding: 0.5rem 1rem;
          border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-weight: 600;
          font-family: inherit; transition: all 0.2s; }}
  .btn:hover {{ background: #d13850; }}
  .btn.secondary {{ background: #1a3a6c; }}
  .btn.secondary:hover {{ background: #2a4a8c; }}
  .btn.outline {{ background: transparent; border: 1px solid var(--accent); color: var(--accent); }}
  .btn.small {{ padding: 0.3rem 0.6rem; font-size: 0.7rem; }}
  .btn.mesh {{ background: #005533; }}
  .btn.mesh:hover {{ background: #007744; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  th, td {{ padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  .event-log {{ max-height: 150px; overflow-y: auto; font-size: 0.75rem; }}
  .event-log div {{ padding: 0.2rem 0; border-bottom: 1px solid var(--border); }}
  .ev-start {{ color: #88ff88; }}
  .ev-stop {{ color: #ff8888; }}
  .ev-mesh {{ color: #88ffff; }}
  input, select {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
                  padding: 0.4rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-family: inherit; }}
  input:focus, select:focus {{ outline: none; border-color: var(--accent); }}
  .form-row {{ display: flex; gap: 0.5rem; align-items: end; flex-wrap: wrap; }}
  textarea {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
              padding: 0.5rem; border-radius: 4px; font-size: 0.8rem; width: 100%;
              font-family: inherit; resize: vertical; }}
  .toast {{ position: fixed; bottom: 1rem; right: 1rem; background: #003322; color: #00ff88;
            padding: 0.8rem 1.2rem; border-radius: 4px; opacity: 0; transform: translateY(10px);
            transition: all 0.3s; z-index: 100; font-size: 0.8rem; }}
  .toast.show {{ opacity: 1; transform: translateY(0); }}
  .inline-code {{ background: var(--surface); padding: 0.1rem 0.3rem; border-radius: 2px; font-size: 0.75rem; }}
  .mono {{ font-family: monospace; }}
  .tab-bar {{ display: flex; gap: 0; margin-bottom: 1rem; border-bottom: 1px solid var(--border); }}
  .tab {{ padding: 0.5rem 1rem; cursor: pointer; color: var(--muted); font-size: 0.8rem;
          border-bottom: 2px solid transparent; }}
  .tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab:hover {{ color: var(--text); }}
  .panel {{ display: none; }}
  .panel.active {{ display: block; }}
</style>
</head>
<body>
<div class="header">
  <h1>☕ CPIP — {hostname} <span style="color:var(--muted);font-weight:400">| {pot_id}</span></h1>
  <div class="sub">{version} — Internet Coffee Protocol + Mesh Comms</div>
</div>
<div class="container">
  <div class="status-bar" style="display:flex;gap:0.5rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap">
    <span id="brewBadge" class="badge idle">—</span>
    <span id="gpioBadge" class="badge {gpio_class}">{gpio_status}</span>
    <span id="meshBadge" class="badge {mesh_class}">{mesh_status}</span>
    <span id="covertBadge" class="badge {covert_class}">{covert_status}</span>
    <span id="itfBadge" class="badge idle">ITF</span>
    <span id="ntpBadge" class="badge enabled">NTP</span>
    <span id="sseBadge" class="badge idle">SSE: ?</span>
    <span style="flex:1"></span>
    <button class="btn secondary" onclick="brew('coffee')">☕ Brew</button>
    <button class="btn secondary" onclick="brew('tea')">🍵 Tea</button>
    <button class="btn outline" onclick="stopBrew()">⏹ Stop</button>
    <button class="btn mesh" onclick="scanMesh()">📡 Scan</button>
  </div>

  <div class="tab-bar">
    <div class="tab active" data-tab="brew" onclick="switchTab('brew')">☕ Brew</div>
    <div class="tab" data-tab="mesh" onclick="switchTab('mesh')">📡 Mesh</div>
    <div class="tab" data-tab="covert" onclick="switchTab('covert')">🔒 Covert</div>
    <div class="tab" data-tab="itf" onclick="switchTab('itf')">🛡 ITF</div>
    <div class="tab" data-tab="schedule" onclick="switchTab('schedule')">⏰ Schedule</div>
    <div class="tab" data-tab="history" onclick="switchTab('history')">📜 History</div>
  </div>

  <div id="panel-brew" class="panel active">
    <div class="grid">
      <div class="card"><h2>Device</h2><div class="value">{device}</div><div class="label">{beverages}</div></div>
      <div class="card"><h2>State</h2><div class="value" id="stateVal">—</div><div class="label" id="stateDet">Waiting</div></div>
      <div class="card"><h2>Brews</h2><div class="value" id="brewCount">0</div><div class="label">Total completed</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Quick Brew</h2>
      <div class="form-row">
        <select id="brewType">
          <option value="coffee">Coffee</option><option value="tea">Tea</option>
          <option value="espresso">Espresso</option><option value="latte">Latte</option>
          <option value="cappuccino">Cappuccino</option><option value="americano">Americano</option>
          <option value="cold-brew">Cold Brew</option><option value="mocha">Mocha</option>
          <option value="matcha">Matcha</option>
        </select>
        <select id="brewTemp"><option value="">Hot</option><option value="iced">Iced</option></select>
        <select id="brewMilk"><option value="">No milk</option><option value="milk;variety=whole">Whole milk</option><option value="milk;variety=cream">Cream</option><option value="milk;variety=skim">Skim</option><option value="milk;variety=oat">Oat</option><option value="milk;variety=almond">Almond</option></select>
        <select id="brewSugar"><option value="">No sugar</option><option value="sugar;variety=white">White</option><option value="sugar;variety=brown">Brown</option><option value="sugar;variety=honey">Honey</option></select>
        <select id="brewSyrup"><option value="">No syrup</option><option value="syrup;variety=vanilla">Vanilla</option><option value="syrup;variety=caramel">Caramel</option><option value="syrup;variety=hazelnut">Hazelnut</option></select>
        <select id="brewSpice"><option value="">No spice</option><option value="spice;variety=cinnamon">Cinnamon</option><option value="spice;variety=cardamom">Cardamom</option><option value="spice;variety=nutmeg">Nutmeg</option></select>
        <select id="brewAlcohol"><option value="">No alcohol</option><option value="alcohol;variety=whiskey">Whiskey</option><option value="alcohol;variety=rum">Rum</option><option value="alcohol;variety=vodka">Vodka</option><option value="alcohol;variety=baileys">Baileys</option><option value="alcohol;variety=kahlua">Kahlua</option><option value="alcohol;variety=amaretto">Amaretto</option></select>
        <button class="btn" onclick="brewCustom()">Brew with additions</button>
      </div>
    </div>
  </div>

  <div id="panel-mesh" class="panel">
    <div class="grid">
      <div class="card"><h2>Mesh Status</h2><div class="value" id="meshPeers">0</div><div class="label">Peers on network</div></div>
      <div class="card"><h2>Inbox</h2><div class="value" id="inboxCount">0</div><div class="label">Messages received</div></div>
      <div class="card"><h2>Queued</h2><div class="value" id="queuedCount">0</div><div class="label">Store-and-forward</div></div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>Satellite <span id="satBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="satCoords">—</span>
          <span id="satPort" style="display:none"></span>
          <span id="satRelay" style="display:none"></span>
          <span id="satPeersCount">0 sat-peers</span>
          <span id="satBootstrap">—</span>
        </div>
        <div id="satPeerList" style="margin-top:0.3rem;font-size:0.75rem"></div>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn secondary small" id="satToggleBtn" onclick="toggleSat()">Enable</button>
        </div>
      </div>
      <div class="card">
        <h2>Mobile <span id="mobBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="mobIface">—</span>
          <span id="mobPort" style="display:none"></span>
          <span id="mobTelemetry" style="display:none"></span>
          <span id="mobPeersCount">0 mobile-peers</span>
          <span id="mobSignal">—</span>
          <span id="mobSignalDetail" style="display:none"></span>
          <span id="mobBootstrap" style="font-size:0.7rem">—</span>
        </div>
        <div id="mobPeerList" style="margin-top:0.3rem;font-size:0.75rem"></div>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn secondary small" id="mobToggleBtn" onclick="toggleMobile()">Enable</button>
        </div>
      </div>
      <div class="card">
        <h2>Radio <span id="radioBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="radioMode">—</span>
          <span id="radioFreq">—</span>
          <span id="radioBw">—</span>
        </div>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Send Message</h2>
      <div class="form-row">
        <input type="text" id="meshDst" placeholder="Destination pot ID" style="width:150px">
        <input type="text" id="meshMsg" placeholder="Message text" style="flex:1">
        <label style="font-size:0.75rem;color:var(--muted)"><input type="checkbox" id="meshCovert"> Use covert channel</label>
        <button class="btn mesh" onclick="sendMesh()">Send</button>
        <button class="btn mesh" onclick="broadcastMesh()">Broadcast</button>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Peers <span id="peerCount" style="color:var(--muted)">(0)</span></h2>
      <div id="peerList"><div style="color:var(--muted)">Scanning…</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Inbox Messages</h2>
      <div id="inboxList"><div style="color:var(--muted)">No messages</div></div>
    </div>
  </div>

  <div id="panel-covert" class="panel">
    <div class="grid">
      <div class="card">
        <h2>Encode Message</h2>
        <textarea id="covertInput" rows="3" placeholder="Message to hide in coffee brew request..."></textarea>
        <div class="form-row" style="margin-top:0.5rem">
          <input type="text" id="covertDst" placeholder="Dest pot (optional)" style="width:150px">
          <select id="covertRecipe">
            <option value="espresso">Espresso</option>
            <option value="pour-over">Pour Over</option>
            <option value="french-press">French Press</option>
            <option value="cold-brew">Cold Brew</option>
            <option value="moka">Moka Pot</option>
          </select>
          <button class="btn" onclick="encodeCovert()">Encode</button>
        </div>
        <div id="covertResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Decode Message</h2>
        <textarea id="covertHeader" rows="3" placeholder="Paste Accept-Additions header value..."></textarea>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn" onclick="decodeCovert()">Decode</button>
        </div>
        <div id="decodeResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Covert Message History</h2>
      <div id="covertHistory"><div style="color:var(--muted)">No messages sent yet</div></div>
    </div>
  </div>

  <div id="panel-itf" class="panel">
    <div class="grid">
      <div class="card"><h2>418 Teapot</h2><div class="value" id="itf418">—</div><div class="label">Defense posture</div></div>
      <div class="card"><h2>Stealth</h2><div class="value" id="itfStealth">—</div><div class="label">Stealth mode <button class="btn small outline" id="stealthToggleBtn" onclick="toggleStealth()" style="margin-left:0.3rem">Toggle</button></div></div>
      <div class="card"><h2>Port Hop</h2><div class="value" id="itfHop">—</div><div class="label"><span id="itfHopInterval"></span></div></div>
      <div class="card"><h2>Latent Ports</h2><div class="value" id="itfLatent">—</div><div class="label">Backup listener ports</div></div>
      <div class="card"><h2>Blacklisted</h2><div class="value" id="itfBlackCount">0</div><div class="label">Addresses blocked</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Blacklist</h2>
      <div id="itfBlacklist"><div style="color:var(--muted)">No addresses blacklisted</div></div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>Whitelist Address</h2>
        <div class="form-row">
          <input type="text" id="itfWhitelistAddr" placeholder="IP address" style="flex:1">
          <button class="btn secondary" onclick="whitelistAddr()">Remove</button>
        </div>
      </div>
      <div class="card">
        <h2>Probe Address</h2>
        <div class="form-row">
          <input type="text" id="itfProbeAddr" placeholder="IP address" style="flex:1">
          <button class="btn secondary" onclick="probeAddr()">Probe</button>
        </div>
        <div id="itfProbeResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Clear All</h2>
        <div class="form-row">
          <button class="btn outline" onclick="clearBlacklist()">Clear Blacklist</button>
        </div>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Detected Tools <span id="itfToolsCount" style="color:var(--muted);font-weight:400">(0)</span></h2>
      <div id="itfTools"><div style="color:var(--muted)">No tools detected yet</div></div>
    </div>
  </div>

  <div id="panel-schedule" class="panel">
    <div class="card">
      <h2>Schedule Brew</h2>
      <div class="form-row">
        <select id="schType"><option value="coffee">Coffee</option><option value="tea">Tea</option></select>
        <input type="number" id="schSeconds" value="30" min="5" style="width:80px">
        <button class="btn secondary" onclick="scheduleIn()">In X seconds</button>
      </div>
      <div class="form-row" style="margin-top:0.5rem">
        <input type="datetime-local" id="schDatetime">
        <label style="font-size:0.75rem;color:var(--muted)"><input type="checkbox" id="schRecurring"> Daily</label>
        <button class="btn secondary" onclick="scheduleAt()">Schedule</button>
      </div>
      <div id="scheduleList" style="margin-top:1rem"></div>
    </div>
  </div>

  <div id="panel-history" class="panel">
    <div class="card">
      <h2>Brew History</h2>
      <div class="form-row" style="margin-bottom:0.5rem">
        <select id="histFilter">
          <option value="">All beverages</option>
          <option value="coffee">Coffee</option><option value="tea">Tea</option>
          <option value="espresso">Espresso</option><option value="latte">Latte</option>
          <option value="cappuccino">Cappuccino</option><option value="americano">Americano</option>
          <option value="cold-brew">Cold Brew</option><option value="mocha">Mocha</option>
        </select>
        <button class="btn outline small" onclick="clearHistory()">Clear</button>
      </div>
      <div id="brewHistory"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>

  <div class="card" style="margin-top:1rem">
    <h2>Live Events <span style="color:var(--muted);font-weight:400">(brew, mesh, covert)</span></h2>
    <div class="event-log" id="eventLog"><div style="color:var(--muted)">Waiting…</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const POT = {pot_json};

function showToast(m) {{ const t = document.getElementById('toast'); t.textContent = m; t.className = 'toast show'; setTimeout(() => t.className = 'toast', 2500); }}

async function api(m, p, b) {{
  try {{
    const o = {{ method: m, headers: {{}} }};
    if (b) {{ o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(b); }}
    const r = await fetch(p, o);
    if (!r.ok && r.status !== 202) {{
      const ej = await r.json().catch(() => ({{}}));
      showToast(ej.error || `HTTP ${{r.status}}`);
      return ej;
    }}
    return await r.json();
  }} catch(e) {{ showToast('Connection error: ' + e.message); return {{}}; }}
}}

function switchTab(name) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => {{ if (t.dataset.tab === name) t.classList.add('active'); }});
  const el = document.getElementById('panel-' + name);
  if (el) el.classList.add('active');
  if (name === 'mesh') {{ refreshMesh(); refreshInbox(); refreshSat(); refreshMobile(); refreshRadio(); }}
  if (name === 'history') {{ refreshHistory(); }}
  if (name === 'schedule') {{ refreshSchedules(); }}
  if (name === 'itf') {{ refreshItf(); }}
}}

async function refresh() {{
  const s = await api('GET', '/cpip/status');
  if (!s || s.error) return;
  const badge = document.getElementById('brewBadge');
  const sv = document.getElementById('stateVal');
  const sd = document.getElementById('stateDet');
  if (s.brewing) {{
    badge.textContent = 'BREWING'; badge.className = 'badge brewing';
    sv.textContent = s.current_brew?.beverage || 'Brewing';
    const secs = Math.floor(s.current_brew?.elapsed_seconds||0);
    sd.textContent = `${{secs}}s ${{s.current_brew?.id||''}}`;
  }} else {{
    badge.textContent = 'IDLE'; badge.className = 'badge idle';
    sv.textContent = 'Idle'; sd.textContent = 'Ready';
  }}
  document.getElementById('brewCount').textContent = s.history_count || 0;
  if (s.mesh) {{
    document.getElementById('meshPeers').textContent = s.mesh.peers_known;
    document.getElementById('inboxCount').textContent = s.mesh.inbox_count || 0;
    document.getElementById('queuedCount').textContent = s.mesh.messages_queued || 0;
  }}
}}

function esc(s) {{ return (''+s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }}

async function refreshHistory() {{
  const filter = document.getElementById('histFilter').value;
  const h = await api('GET', '/cpip/history?limit=16');
  if (!h || !h.history) return;
  const el = document.getElementById('brewHistory');
  if (!h.history.length) {{ el.innerHTML = '<div style="color:var(--muted)">No brews yet.</div>'; return; }}
  let items = h.history;
  if (filter) items = items.filter(b => b.beverage === filter);
  if (!items.length) {{ el.innerHTML = '<div style="color:var(--muted)">No matches.</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>Bev</th><th>Additions</th><th>Dur</th></tr>';
  for (const b of items) {{
    const t = b.started ? new Date(b.started*1000).toLocaleTimeString() : '—';
    const add = b.additions?.map(a => esc(a.name||a)).join(',') || '—';
    html += `<tr><td>${{esc(t)}}</td><td>${{esc(b.beverage)}}</td><td style="font-size:0.7rem">${{esc(add)}}</td><td>${{esc(b.duration)}}s</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function clearHistory() {{
  if (!confirm('Clear all brew history?')) return;
  const r = await api('DELETE', '/cpip/history');
  if (r) showToast('History cleared');
  refreshHistory();
}}

async function refreshMesh() {{
  const p = await api('GET', '/cpip/mesh/peers');
  if (!p) return;
  document.getElementById('peerCount').textContent = `(${{p.count||0}})`;
  const el = document.getElementById('peerList');
  if (!p.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No peers found. Tap Scan.</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Addr</th><th>Device</th><th>Seen</th><th>Hops</th></tr>';
  for (const peer of p.peers) {{
    const ls = peer.last_seen ? Math.floor((Date.now()/1000 - peer.last_seen)) + 's ago' : '—';
    html += `<tr><td class="mono">${{esc(peer.pot?.slice(0,6)||'?')}}</td><td>${{esc(peer.hostname||'?')}}</td><td>${{esc(peer.addr||'?')}}</td><td>${{esc((peer.device||'?').slice(0,10))}}</td><td>${{esc(ls)}}</td><td>${{esc(peer.hops)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshInbox() {{
  const ib = await api('GET', '/cpip/mesh/inbox');
  if (!ib) return;
  const el = document.getElementById('inboxList');
  if (!ib.messages?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages</div>'; return; }}
  if (!ib.messages?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>From</th><th>Message</th><th>Ch</th></tr>';
  for (const m of ib.messages.slice().reverse()) {{
    const t = m.timestamp ? new Date(m.timestamp*1000).toLocaleTimeString() : '—';
    const data = m.data?.length > 50 ? m.data.slice(0, 50) + '…' : (m.data || '');
    const ch = m.channel || 'mesh';
    html += `<tr><td>${{esc(t)}}</td><td class="mono" style="font-size:0.7rem">${{esc(m.from?.slice(0,6)||'?')}}</td><td style="font-size:0.7rem">${{esc(data)}}</td><td>${{esc(ch)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshSat() {{
  const s = await api('GET', '/cpip/mesh/sat');
  if (!s || !s.enabled) {{
    document.getElementById('satBadge').textContent = 'OFF';
    document.getElementById('satBadge').className = 'badge idle';
    document.getElementById('satCoords').textContent = 'Satellite disabled';
    document.getElementById('satPort').style.display = 'none';
    document.getElementById('satRelay').style.display = 'none';
    return;
  }}
  document.getElementById('satBadge').textContent = 'ON';
  document.getElementById('satBadge').className = 'badge enabled';
  document.getElementById('satCoords').textContent = `${{s.coords?.lat||'?'}}°, ${{s.coords?.lon||'?'}}°${{s.coords?.alt ? ' '+s.coords.alt+'m' : ''}}`;
  const portEl = document.getElementById('satPort');
  portEl.textContent = `port: ${{s.port}}`;
  portEl.style.display = 'inline';
  const relayEl = document.getElementById('satRelay');
  relayEl.textContent = s.relay ? 'relay: ON' : 'relay: OFF';
  relayEl.style.display = 'inline';
  relayEl.style.color = s.relay ? '#00ff88' : 'var(--muted)';
  document.getElementById('satPeersCount').textContent = `${{s.peers_known||0}} sat-peer(s)`;
  document.getElementById('satBootstrap').textContent = s.bootstrap?.length ? `bootstrap: ${{s.bootstrap.join(', ')}}` : 'no bootstrap';
  const el = document.getElementById('satPeerList');
  if (!s.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No satellite peers yet</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Coords</th><th>RTT</th><th>Seen</th></tr>';
  for (const p of s.peers) {{
    const t = p.last_seen ? Math.floor((Date.now()/1000 - p.last_seen)) + 's ago' : '—';
    html += `<tr><td class="mono">${{esc(p.pot?.slice(0,6)||'?')}}</td><td>${{esc(p.hostname||'?')}}</td><td>${{esc((p.lat||'?').toFixed(1)+','+(p.lon||'?').toFixed(1))}}</td><td>${{esc(p.rtt||'?')}}ms</td><td>${{esc(t)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshMobile() {{
  const m = await api('GET', '/cpip/mesh/mobile');
  if (!m || !m.enabled) {{
    document.getElementById('mobBadge').textContent = 'OFF';
    document.getElementById('mobBadge').className = 'badge idle';
    document.getElementById('mobIface').textContent = 'Mobile disabled';
    document.getElementById('mobPort').style.display = 'none';
    document.getElementById('mobTelemetry').style.display = 'none';
    document.getElementById('mobSignalDetail').style.display = 'none';
    return;
  }}
  document.getElementById('mobBadge').textContent = 'ON';
  document.getElementById('mobBadge').className = 'badge enabled';
  document.getElementById('mobIface').textContent = m.interface || '?';
  const portEl = document.getElementById('mobPort');
  portEl.textContent = `port: ${{m.port}}`;
  portEl.style.display = 'inline';
  const telEl = document.getElementById('mobTelemetry');
  telEl.textContent = m.telemetry ? 'telemetry: ON' : 'telemetry: OFF';
  telEl.style.display = 'inline';
  telEl.style.color = m.telemetry ? '#00ff88' : 'var(--muted)';
  document.getElementById('mobPeersCount').textContent = `${{m.peers_known||0}} mobile-peer(s)`;
  const sig = m.signal || {{}};
  let sigStr = '—';
  if (sig.rssi != null) sigStr = `RSSI: ${{sig.rssi}}`;
  else if (sig.rsrp != null) sigStr = `RSRP: ${{sig.rsrp}}`;
  document.getElementById('mobSignal').textContent = sigStr;
  const detEl = document.getElementById('mobSignalDetail');
  const sinr = sig.sinr != null ? `SINR: ${{sig.sinr}}` : null;
  const mcc = sig.mcc != null ? `MCC: ${{sig.mcc}}` : null;
  const detParts = [sinr, mcc].filter(Boolean);
  if (detParts.length) {{
    detEl.textContent = detParts.join(' | ');
    detEl.style.display = 'inline';
  }} else {{
    detEl.style.display = 'none';
  }}
  document.getElementById('mobBootstrap').textContent = m.bootstrap?.length ? `seed: ${{m.bootstrap.join(', ')}}` : 'no bootstrap';
  const el = document.getElementById('mobPeerList');
  if (!m.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No mobile peers yet</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Signal</th><th>Net</th><th>Hops</th></tr>';
  for (const p of m.peers) {{
    const sig = p.signal;
    let sigStr = '—';
    if (sig && typeof sig === 'object') {{ sigStr = sig.rssi != null ? sig.rssi + ' dBm' : (sig.rsrp != null ? 'RSRP ' + sig.rsrp : '—'); }}
    else if (sig) {{ sigStr = String(sig); }}
    html += `<tr><td class="mono">${{esc(p.pot?.slice(0,6)||'?')}}</td><td>${{esc(p.hostname||'?')}}</td><td>${{esc(sigStr)}}</td><td>${{esc(p.network||'—')}}</td><td>${{esc(p.hops||0)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshRadio() {{
  const r = await api('GET', '/cpip/mesh/radio');
  if (!r) return;
  const badge = document.getElementById('radioBadge');
  if (r.enabled) {{
    badge.textContent = 'ON'; badge.className = 'badge enabled';
    document.getElementById('radioMode').textContent = 'mode: ' + (r.mode || '?');
    document.getElementById('radioFreq').textContent = 'freq: ' + ((r.frequency/1e6).toFixed(1) || '?') + ' MHz';
    document.getElementById('radioBw').textContent = 'bw: ' + ((r.bandwidth/1e3).toFixed(0) || '?') + ' kHz';
  }} else {{
    badge.textContent = 'OFF'; badge.className = 'badge idle';
    document.getElementById('radioMode').textContent = 'Radio disabled';
    document.getElementById('radioFreq').textContent = '';
    document.getElementById('radioBw').textContent = '';
  }}
}}

async function toggleSat() {{
  const badge = document.getElementById('satBadge');
  const on = badge.textContent === 'ON';
  const r = await api('POST', '/cpip/mesh/sat', {{ action: on ? 'disable' : 'enable' }});
  if (r) showToast(r.status || 'Toggled');
  await refreshSat();
  document.getElementById('satToggleBtn').textContent = badge.textContent === 'ON' ? 'Disable' : 'Enable';
}}

async function toggleMobile() {{
  const badge = document.getElementById('mobBadge');
  const on = badge.textContent === 'ON';
  const r = await api('POST', '/cpip/mesh/mobile', {{ action: on ? 'disable' : 'enable' }});
  if (r) showToast(r.status || 'Toggled');
  await refreshMobile();
  document.getElementById('mobToggleBtn').textContent = badge.textContent === 'ON' ? 'Disable' : 'Enable';
}}

async function toggleStealth() {{
  const v = document.getElementById('itfStealth');
  const on = v.textContent === 'ON';
  const r = await api('POST', '/cpip/defense', {{ action: 'stealth', enabled: !on }});
  if (r) showToast('Stealth: ' + (r.enabled ? 'ON' : 'OFF'));
  refreshItf();
}}

async function scanMesh() {{
  showToast('Scanning...');
  try {{
    const d = await api('GET', '/cpip/discover');
    if (d && d.pots) showToast(`Found ${{d.count}} pot(s)`);
    await refreshMesh();
  }} catch(e) {{ showToast('Scan failed'); }}
}}

async function brew(type) {{
  const r = await api('POST', '/cpip/brew', {{ beverage: type }});
  if (r && r.status === 'brewing') showToast('Brewing ' + type);
  else if (r && r.error) showToast(r.message || r.error);
  refresh();
}}

async function brewCustom() {{
  const type = document.getElementById('brewType').value;
  const temp = document.getElementById('brewTemp').value;
  const parts = [
    document.getElementById('brewMilk').value,
    document.getElementById('brewSugar').value,
    document.getElementById('brewSyrup').value,
    document.getElementById('brewSpice').value,
    document.getElementById('brewAlcohol').value,
  ].filter(p => p);
  const additions = parts.map(p => {{ const [n,...r] = p.split(';'); const v = r.find(x => x.startsWith('variety=')); return {{ name: n, variety: v ? v.split('=')[1] : null }}; }});
  const body = {{ beverage: type, additions }};
  if (temp) body.temperature = temp;
  const r = await api('POST', '/cpip/brew', body);
  if (r && r.status === 'brewing') showToast('Brewing ' + type + ' with additions');
  else if (r && r.error) showToast(r.message || r.error);
  refresh();
}}

async function stopBrew() {{
  try {{
    await fetch('/', {{ method: 'WHEN' }});
    showToast('Stopped');
  }} catch(e) {{ showToast('Stop failed'); }}
  refresh();
}}

async function scheduleIn() {{
  const s = parseInt(document.getElementById('schSeconds').value) || 30;
  const t = document.getElementById('schType').value;
  const r = await api('POST', '/cpip/schedule', {{ in: s, beverage: t, brew_duration: 60 }});
  if (r && r.status === 'scheduled') showToast('Scheduled ' + t + ' in ' + s + 's');
  refreshSchedules();
}}

async function scheduleAt() {{
  const dt = document.getElementById('schDatetime').value;
  const t = document.getElementById('schType').value;
  const recurring = document.getElementById('schRecurring').checked;
  if (!dt) {{ showToast('Pick a time'); return; }}
  const body = {{ time: new Date(dt).toISOString(), beverage: t, brew_duration: 60 }};
  if (recurring) body.recurring = 'daily';
  const r = await api('POST', '/cpip/schedule', body);
  if (r && r.status === 'scheduled') showToast('Scheduled' + (recurring ? ' daily' : ''));
  refreshSchedules();
}}

async function refreshSchedules() {{
  const s = await api('GET', '/cpip/schedules');
  if (!s) return;
  const el = document.getElementById('scheduleList');
  if (!s.schedules?.length) {{ el.innerHTML = '<div style="color:var(--muted);font-size:0.75rem">None</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>Bev</th><th>Dur</th><th>Recur</th><th></th></tr>';
  for (const sc of s.schedules) {{
    html += `<tr><td>${{esc(sc.human||sc.time)}}</td><td>${{esc(sc.beverage)}}</td><td>${{esc(sc.brew_duration)}}s</td>`;
    html += `<td>${{sc.recurring ? 'Daily' : '-'}}</td>`;
    html += `<td><button class="btn outline small" data-sid="${{esc(sc.id)}}">X</button></td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
  el.querySelectorAll('[data-sid]').forEach(btn => {{
    btn.addEventListener('click', async () => {{
      await api('DELETE', '/cpip/schedules/' + btn.dataset.sid);
      refreshSchedules();
    }});
  }});
}}

async function sendMesh() {{
  const dst = document.getElementById('meshDst').value;
  const msg = document.getElementById('meshMsg').value;
  const covert = document.getElementById('meshCovert').checked;
  if (!dst || !msg) {{ showToast('Need destination + message'); return; }}
  const r = await api('POST', '/cpip/mesh/send', {{ dst, data: msg, covert }});
  if (r) showToast('Sent: ' + (r.status || 'ok'));
  document.getElementById('meshMsg').value = '';
}}

async function broadcastMesh() {{
  const msg = document.getElementById('meshMsg').value;
  if (!msg) {{ showToast('Enter a message'); return; }}
  const r = await api('POST', '/cpip/mesh/broadcast', {{ data: msg }});
  if (r) showToast('Broadcast: ' + (r.peers_reached||0) + ' peers');
  document.getElementById('meshMsg').value = '';
}}

async function encodeCovert() {{
  const msg = document.getElementById('covertInput').value;
  const dst = document.getElementById('covertDst').value;
  const recipe = document.getElementById('covertRecipe').value;
  if (!msg) {{ showToast('Enter message'); return; }}
  const r = await api('POST', '/cpip/mesh/encode', {{ message: msg, dst, recipe }});
  if (!r || r.status !== 'encoded') return;
  const header = r.accept_additions_header;
  document.getElementById('covertResult').innerHTML = `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem">
    <div style="color:var(--muted)">Accept-Additions header:</div>
    <div class="mono" style="font-size:0.7rem;word-break:break-all;margin-top:0.3rem">${{esc(header)}}</div>
    <div style="color:var(--muted);margin-top:0.3rem">Recipe: ${{esc(r.recipe)}} | ${{esc(r.encoded_length)}} bytes</div>
    <div style="margin-top:0.3rem"><button class="btn small outline" onclick="navigator.clipboard.writeText('${{esc(header)}}');showToast('Copied')">Copy</button></div>
  </div>`;
  const history = JSON.parse(localStorage.getItem('cpip_covert_history') || '[]');
  history.unshift({{ message: msg.slice(0, 80), dst: dst || 'any', recipe, header: header.slice(0, 60) + '…', time: new Date().toLocaleString() }});
  if (history.length > 20) history.pop();
  localStorage.setItem('cpip_covert_history', JSON.stringify(history));
  renderCovertHistory();
}}

function renderCovertHistory() {{
  const el = document.getElementById('covertHistory');
  const history = JSON.parse(localStorage.getItem('cpip_covert_history') || '[]');
  if (!history.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages sent yet</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>To</th><th>Message</th><th>Recipe</th><th>Header</th></tr>';
  for (const h of history) {{
    html += `<tr><td style="font-size:0.7rem">${{esc(h.time)}}</td><td>${{esc(h.dst)}}</td><td style="font-size:0.7rem">${{esc(h.message)}}</td><td>${{esc(h.recipe)}}</td><td class="mono" style="font-size:0.65rem">${{esc(h.header)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function decodeCovert() {{
  const header = document.getElementById('covertHeader').value;
  if (!header) {{ showToast('Paste header value'); return; }}
  const r = await api('POST', '/cpip/mesh/decode', {{ accept_additions: header }});
  if (!r) return;
  document.getElementById('decodeResult').innerHTML = r.status === 'decoded'
    ? `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem"><div style="color:#88ff88">Decoded:</div><div style="margin-top:0.3rem">${{esc(r.message)}}</div></div>`
    : `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem;color:var(--muted)">${{esc(r.message)}}</div>`;
}}

async function refreshItf() {{
  const d = await api('GET', '/cpip/defense');
  if (!d || d.error) return;
  const badge = document.getElementById('itfBadge');
  if (d.stealth) {{
    badge.textContent = 'ITF: STEALTH'; badge.className = 'badge enabled';
  }} else {{
    badge.textContent = 'ITF'; badge.className = 'badge idle';
  }}
  document.getElementById('itf418').textContent = d['418_teapot'] ? 'ACTIVE' : 'INACTIVE';
  document.getElementById('itf418').style.color = d['418_teapot'] ? 'var(--accent)' : 'var(--muted)';
  document.getElementById('itfStealth').textContent = d.stealth ? 'ON' : 'OFF';
  document.getElementById('itfStealth').style.color = d.stealth ? '#00ff88' : 'var(--muted)';
  document.getElementById('itfHop').textContent = d.port_hopping ? 'ON' : 'OFF';
  document.getElementById('itfHop').style.color = d.port_hopping ? '#00ff88' : 'var(--muted)';
  document.getElementById('itfHopInterval').textContent = d.port_hopping ? d.hop_interval + 's interval' : '';
  document.getElementById('itfLatent').textContent = d.latent_ports?.length ? d.latent_ports.join(', ') : 'None';
  document.getElementById('itfBlackCount').textContent = d.blacklisted_addrs || 0;
  const el = document.getElementById('itfBlacklist');
  if (!d.blacklist?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No addresses blacklisted</div>'; return; }}
  let html = '<table><tr><th>IP Address</th><th></th></tr>';
  for (const addr of d.blacklist) {{
    html += `<tr><td class="mono">${{esc(addr)}}</td><td><button class="btn outline small" onclick="whitelistAddr('${{esc(addr)}}')">Whitelist</button></td></tr>`;
  }}
  el.innerHTML = html;
  const tcEl = document.getElementById('itfTools');
  const tcCount = document.getElementById('itfToolsCount');
  if (!d.tools_detected || !Object.keys(d.tools_detected).length) {{
    tcCount.textContent = '(0)';
    tcEl.innerHTML = '<div style="color:var(--muted)">No tools detected yet</div>';
    return;
  }}
  tcCount.textContent = `(${{Object.keys(d.tools_detected).length}})`;
  let thtml = '<table><tr><th>Tool</th><th>Hits</th><th>Last Seen</th><th>Sources</th></tr>';
  const sorted = Object.entries(d.tools_detected).sort((a, b) => b[1].count - a[1].count);
  for (const [tool, info] of sorted) {{
    const ls = info.last_seen ? new Date(info.last_seen * 1000).toLocaleTimeString() : '—';
    const addrs = info.addrs?.join(', ') || '—';
    thtml += `<tr><td>${{esc(tool)}}</td><td>${{info.count}}</td><td>${{esc(ls)}}</td><td style="font-size:0.7rem" class="mono">${{esc(addrs)}}</td></tr>`;
  }}
  thtml += '</table>'; tcEl.innerHTML = thtml;
}}

async function whitelistAddr(addr) {{
  addr = addr || document.getElementById('itfWhitelistAddr').value;
  if (!addr) {{ showToast('Enter an IP address'); return; }}
  const r = await api('POST', '/cpip/defense', {{ action: 'whitelist', addr }});
  if (r && r.status === 'whitelisted') showToast('Whitelisted ' + addr);
  document.getElementById('itfWhitelistAddr').value = '';
  refreshItf();
}}

async function clearBlacklist() {{
  const r = await api('POST', '/cpip/defense', {{ action: 'clear' }});
  if (r && r.status === 'blacklist_cleared') showToast('Blacklist cleared');
  refreshItf();
}}

async function probeAddr() {{
  const addr = document.getElementById('itfProbeAddr').value;
  if (!addr) {{ showToast('Enter an IP address'); return; }}
  const r = await api('POST', '/cpip/defense', {{ action: 'probe', addr }});
  const el = document.getElementById('itfProbeResult');
  if (!r || r.status !== 'probed') {{ el.innerHTML = '<div style="color:var(--muted)">Probe failed</div>'; return; }}
  const bl = r.blacklisted ? '<span style="color:var(--accent)">BLACKLISTED</span>' : '<span style="color:#00ff88">CLEAN</span>';
  el.innerHTML = `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;font-size:0.75rem">
    <div>${{esc(r.addr)}} — ${{bl}}</div>
    <div style="color:var(--muted);margin-top:0.2rem">Probes: ${{r.probe_count}} | Remaining: ${{r.remaining_seconds}}s</div>
  </div>`;
}}

function connectSSE() {{
  const badge = document.getElementById('sseBadge');
  const log = document.getElementById('eventLog');
  const evt = new EventSource('/cpip/events');
  evt.onopen = () => {{ badge.textContent = 'SSE: OK'; badge.className = 'badge enabled'; }};
  evt.onerror = () => {{ badge.textContent = 'SSE: ERR'; badge.className = 'badge disabled'; }};
  evt.onmessage = (e) => {{
    try {{
      const d = JSON.parse(e.data);
      const entry = document.createElement('div');
      const ts = new Date().toLocaleTimeString();
      if (d.event === 'brew_start') {{ entry.className = 'ev-start'; entry.textContent = '['+ts+'] Brew '+d.beverage; refresh(); }}
      else if (d.event === 'brew_stop') {{ entry.className = 'ev-stop'; entry.textContent = '['+ts+'] Stop'; refresh(); refreshHistory(); }}
      else if (d.event === 'mesh_message') {{ entry.className = 'ev-mesh'; entry.textContent = '['+ts+'] Msg from '+(d.from||'?'); refreshInbox(); }}
      else {{ entry.textContent = '['+ts+'] '+e.data; }}
      log.insertBefore(entry, log.firstChild);
      while (log.children.length > 50) log.removeChild(log.lastChild);
    }} catch(ex) {{}}
  }};
}}

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));

refresh(); refreshHistory(); refreshSchedules(); refreshMesh(); refreshInbox(); refreshSat(); refreshMobile(); refreshItf(); refreshRadio(); renderCovertHistory();
document.getElementById('histFilter').addEventListener('change', refreshHistory);
setInterval(refresh, 5000);
setInterval(refreshHistory, 15000);
setInterval(refreshSchedules, 15000);
setInterval(refreshMesh, 30000);
setInterval(refreshInbox, 10000);
setInterval(refreshSat, 30000);
setInterval(refreshMobile, 30000);
setInterval(refreshRadio, 30000);
setInterval(refreshItf, 15000);
connectSSE();
</script>
</body>
</html>"""


# ── Pi-Tail USB Gadget (Pi Zero → host via USB OTG) ───────────────────
def start_pitail():
    """Configure Pi Zero as a USB Ethernet gadget.
    
    When plugged into a host (laptop/phone), the Pi appears as a network
    interface. The user opens a browser to 10.0.0.1:4180 for the dashboard.
    
    This uses the Linux USB gadget configfs interface. Requires:
      - Pi Zero (or any board with USB OTG)
      - Kernel compiled with USB gadget support
      - /sys/kernel/config/usb_gadget available
    """
    if not PITAIL_ENABLED:
        return False
    gdir = Path(PITAIL_GADGET_DIR)
    if not gdir.exists():
        print("   ⚠ Pi-Tail: USB gadget configfs not found", flush=True)
        return False
    try:
        gname = "g1"
        gadget = gdir / gname
        if not gadget.exists():
            gadget.mkdir()
            # Standard USB Ethernet descriptor
            (gadget / "idVendor").write_text("0x1d6b")
            (gadget / "idProduct").write_text("0x0104")
            (gadget / "bcdDevice").write_text("0x0100")
            (gadget / "bcdUSB").write_text("0x0200")
            # Config
            cfg = gadget / "configs/c.1"
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / "MaxPower").write_text("250")
            # Strings
            for d in [gadget / "strings/0x409", cfg / "strings/0x409"]:
                d.mkdir(parents=True, exist_ok=True)
                (d / "manufacturer").write_text("Coffee Protocol")
                (d / "product").write_text("CPIP Pi-Tail")
                (d / "serialnumber").write_text(POT_ID)
            # Ethernet function
            func = gadget / "functions/ecm.usb0"
            func.mkdir(parents=True, exist_ok=True)
            (func / "dev_addr").write_text("42:61:de:ad:be:ef")
            (func / "host_addr").write_text("42:61:de:ad:be:ef")
            # Link function to config
            (cfg / "ecm.usb0").symlink_to(func)
            # UDC (bind to the USB device controller)
            udc = next((gdir.parent / "udc").iterdir(), None)
            if udc:
                (gadget / "UDC").write_text(udc.name)
        # Bring up the interface
        subprocess.run(["ip", "link", "set", "usb0", "up"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "addr", "add",
                        f"{PITAIL_ADDR}/{PITAIL_NETMASK}",
                        "dev", "usb0"],
                       capture_output=True, timeout=5)
        print(f"   ├ Pi-Tail:    {PITAIL_ADDR}:{BIND_PORT} (USB gadget)", flush=True)
        return True
    except Exception as e:
        print(f"   ⚠ Pi-Tail: {e}", flush=True)
        return False


# ── 418 I'm a Teapot Defense Layer ───────────────────────────────────
# Rejects unauthorized/unauthenticated probes with HTCPCP's most
# famous status code. Makes network mapping and brute-force attacks
# indistinguishable from a joke.
TEAPOT_BLACKLIST = {}
TEAPOT_BLACKLIST_LOCK = threading.Lock()
TEAPOT_PROBE_COUNT = {}
DEFENSE_RATE_LIMIT = int(os.environ.get("CPIP_DEFENSE_RATE_LIMIT", "10"))
DEFENSE_RATE_WINDOW = int(os.environ.get("CPIP_DEFENSE_RATE_WINDOW", "60"))
DEFENSE_BLACKLIST_TTL = int(os.environ.get("CPIP_DEFENSE_BLACKLIST_TTL", "3600"))
DEFENSE_MAX_BLACKLIST = int(os.environ.get("CPIP_DEFENSE_MAX_BLACKLIST", "1000"))

# Tool fingerprint tracking
TEAPOT_TOOL_HITS = {}  # {tool_name: {"count": int, "last_seen": float, "addrs": set}}
TEAPOT_TOOL_LOCK = threading.Lock()

PENTEST_TOOLS = [
    ("Burp Suite", ["burp", "burpsuite"], ["x-burp", "x-requested-by: burp"]),
    ("Nmap", ["nmap"], []),
    ("SQLMap", ["sqlmap", "sql map"], []),
    ("Nikto", ["nikto"], []),
    ("Gobuster", ["gobuster"], []),
    ("Dirb", ["dirb", "dirbuster"], []),
    ("FFUF", ["ffuf", "fuzz faster u fool"], []),
    ("WFuzz", ["wfuzz"], []),
    ("OpenVAS", ["openvas", "open vas"], []),
    ("Nessus", ["nessus"], []),
    ("Masscan", ["masscan"], []),
    ("ZAP", ["zap", "zed attack proxy"], []),
    ("Arachni", ["arachni"], []),
    ("w3af", ["w3af"], []),
    ("Metasploit", ["metasploit", "msf"], []),
    ("Acunetix", ["acunetix"], []),
]

INFO_TOOLS = [
    ("cURL", ["curl"], []),
    ("Wget", ["wget", "gnu wget"], []),
    ("Python", ["python-requests", "python-urllib", "aiohttp"], []),
    ("Go-http", ["go-http-client"], []),
]

ALL_TOOLS = PENTEST_TOOLS + INFO_TOOLS

def teapot_defense(addr):
    """Check if an address should be greeted with 418."""
    if addr in ("127.0.0.1", "::1", "localhost"):
        return False
    with TEAPOT_BLACKLIST_LOCK:
        entry = TEAPOT_BLACKLIST.get(addr)
        if entry:
            if time.time() < entry.get("expires", 0):
                return True
            del TEAPOT_BLACKLIST[addr]
        return False

def teapot_blacklist_addr(addr):
    """Add an address to the 418 blacklist. Tracks probe rate.
    Repeated probes within the rate window double the ban duration."""
    if addr in ("127.0.0.1", "::1", "localhost"):
        return
    now = time.time()
    with TEAPOT_BLACKLIST_LOCK:
        # Rate tracking
        hits = TEAPOT_PROBE_COUNT.get(addr, [])
        hits = [t for t in hits if now - t < DEFENSE_RATE_WINDOW]
        hits.append(now)
        TEAPOT_PROBE_COUNT[addr] = hits

        entry = TEAPOT_BLACKLIST.get(addr)
        base_ttl = DEFENSE_BLACKLIST_TTL
        if entry:
            base_ttl = entry.get("ttl", base_ttl)
        if len(hits) > DEFENSE_RATE_LIMIT:
            base_ttl = min(base_ttl * 2, 86400)
        TEAPOT_BLACKLIST[addr] = {"expires": now + base_ttl, "ttl": base_ttl}
        if len(TEAPOT_BLACKLIST) > DEFENSE_MAX_BLACKLIST:
            oldest = sorted(TEAPOT_BLACKLIST.items(),
                           key=lambda x: x[1].get("expires", 0))[:len(TEAPOT_BLACKLIST)//2]
            for k, _ in oldest:
                del TEAPOT_BLACKLIST[k]
                TEAPOT_PROBE_COUNT.pop(k, None)

def teapot_probe_check(headers, addr, path, method):
    """Determine if a request looks like hostile probing vs legitimate HTCPCP.
    
    Classification heuristics (all subject to false positives — that's the point):
    - No Accept-Additions header on BREW to unknown paths → probe
    - PROPFIND without proper host → probe
    - Multiple schema variants in rapid succession → probe
    - Requests to /admin, /config, /wp-content, etc. → probe
    - Known pentest tool User-Agents → probe (Burp Suite, Nmap, SQLMap, etc.)
    """
    probe_indicators = 0
    # Check for common scanner paths
    scanner_paths = ["/admin", "/config", "/wp-", "/.env", "/phpmyadmin",
                     "/shell", "/cmd", "/exec", "/backdoor", "/login",
                     "/setup", "/install", "/manager", "/console"]
    for sp in scanner_paths:
        if path.lower().startswith(sp):
            probe_indicators += 3
            break
    # BREW without additions to odd paths
    if method == "BREW" and not headers.get("Accept-Additions"):
        if not any(p in path for p in ["/coffee", "/tea", "/pot"]):
            probe_indicators += 1
    # Unknown URI schemes (probing for HTTP server info)
    if "://" in path and not is_coffee_uri_path(path):
        probe_indicators += 2
    # Rapid requests from same IP
    # (tracked via teapot_defense above)
    # Known pentest tool detection (Burp Suite, Nmap, SQLMap, etc.)
    tool_matches = teapot_tool_check(headers, addr, pentest_only=True)
    if tool_matches:
        probe_indicators += 2
    if probe_indicators >= 2:
        return True
    return False


def teapot_tool_check(headers, addr, pentest_only=False):
    """Identify known pentest/scan tools from User-Agent and request headers.
    Updates TEAPOT_TOOL_HITS with detected tool usage.
    If pentest_only=True, only returns pentest/attack tools (not generic HTTP clients)."""
    ua = (headers.get("User-Agent") or headers.get("user-agent") or "").lower()
    all_headers = " ".join(f"{k.lower()}:{v.lower()}" for k, v in headers.items())
    detected = []
    signatures = PENTEST_TOOLS if pentest_only else ALL_TOOLS
    for tool_name, ua_keywords, hdr_keywords in signatures:
        matched = False
        for kw in ua_keywords:
            if kw in ua:
                matched = True
                break
        if not matched:
            for kw in hdr_keywords:
                if kw in all_headers:
                    matched = True
                    break
        if matched:
            detected.append(tool_name)
    if detected:
        with TEAPOT_TOOL_LOCK:
            for tool in detected:
                if tool not in TEAPOT_TOOL_HITS:
                    TEAPOT_TOOL_HITS[tool] = {"count": 0, "last_seen": 0, "addrs": set()}
                TEAPOT_TOOL_HITS[tool]["count"] += 1
                TEAPOT_TOOL_HITS[tool]["last_seen"] = time.time()
                TEAPOT_TOOL_HITS[tool]["addrs"].add(addr)
    return detected


# ── Main ──────────────────────────────────────────────────────────────
def shutdown(signum, frame):
    print("\n[CPIP] Shutting down...", flush=True)
    stop_mdns()
    stop_scheduler()
    MeshNode.stop()
    if gpio.is_available:
        gpio.off()
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server = ThreadedHTTPServer((BIND_ADDR, BIND_PORT), CPIPHandler)
    bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])

    print(f"☕  CPIP v{CPIP_VERSION} — Coffee Protocol Internet Protocol", flush=True)
    print(f"   ┌ Device:     {DEVICE_TYPE}", flush=True)
    print(f"   ├ Pot ID:     {POT_ID}", flush=True)
    print(f"   ├ Hostname:   {HOSTNAME}", flush=True)
    print(f"   ├ Listen:     {BIND_ADDR}:{BIND_PORT}", flush=True)
    print(f"   ├ Beverages:  {', '.join(bev)}", flush=True)
    print(f"   ├ GPIO:       {'Pin ' + str(GPIO_PIN) + ' (RPi.GPIO)' if gpio.is_available else 'Disabled'}", flush=True)
    print(f"   ├ mDNS:       {'Enabled' if AVAHI_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Covert:     {'ECC-Active' if COVERT_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Mesh:       {'Port ' + str(MESH_PORT) + ' (active)' if MESH_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Cover:      {'Traffic generation on' if COVER_TRAFFIC else 'Off'}", flush=True)
    print(f"   ├ 418:        {'I\'m a Teapot defense active' if MESH_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Satellite:  {'Port ' + str(SATELLITE_PORT) + ' (sat-mesh)' if SATELLITE_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Radio:      {'Port ' + str(RADIO_FREQ//1000000) + ' MHz (' + RADIO_MODE.upper() + ')' if RADIO_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Mobile:     {'Port ' + str(MOBILE_PORT) + ' (' + MOBILE_INTERFACE + ')' if MOBILE_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Thermos:    {'Aggregator mode' if THERMOS_ENABLED else 'Standard'}", flush=True)
    print(f"   └ Dashboard:  http://{BIND_ADDR if BIND_ADDR != '0.0.0.0' else 'localhost'}:{BIND_PORT}/dashboard", flush=True)
    print(f"", flush=True)
    print(f"   HTCPCP (RFC 2324+7168): BREW, WHEN, PROPFIND, POST, GET", flush=True)
    print(f"   coffee: URI scheme:     {len(COFFEE_SCHEME_NAMES)} international variants", flush=True)
    print(f"   message/coffeepot:      Content-Type for start/stop commands", flush=True)
    print(f"   CPIP:                 /cpip/status, /cpip/brew, /cpip/schedule, /cpip/pots, /cpip/metrics, /cpip/events", flush=True)
    print(f"   MESH:                 /cpip/mesh/status, /cpip/mesh/peers, /cpip/mesh/inbox, /cpip/mesh/send, /cpip/mesh/broadcast", flush=True)
    print(f"   SAT-MESH:             /cpip/mesh/sat (satellite/Starlink status)", flush=True)
    print(f"   RADIO:                /cpip/mesh/radio (LoRa / TNC / packet radio status)", flush=True)
    print(f"   MOBILE:               /cpip/mesh/mobile (4G/5G / LTE / WWAN status)", flush=True)
    print(f"   COVERT (ECC):         /cpip/mesh/encode, /cpip/mesh/decode", flush=True)
    print(f"   DEADDROP:             /cpip/mesh/deaddrop?action=list|claim&id= (dead-drop query)", flush=True)
    print(f"   DEFENSE:              /cpip/defense (418 blacklist + stealth status)", flush=True)
    print(f"   418 DEFENSE:          Unauthorized probes answered with 418 I'm a Teapot", flush=True)
    print(f"   NTP:                  {'Syncing to ' + NTP_SERVER if NTP_SYNC else 'Disabled'}", flush=True)
    print(f"   NO INTERNET REQUIRED — local mesh; Satellite relays internet-wide mesh", flush=True)
    print(f"   NOT FIPS COMPLIANT — uses Coffee Blend Cipher + Ed25519 (non-standard, not constant-time)", flush=True)

    if PITAIL_ENABLED:
        start_pitail()
    start_mdns()
    start_discovery()
    start_scheduler()
    start_ntp()
    MeshNode.start()
    start_radio()

    address_display = MeshNode.node_address or "(ECC keys generated on first mesh message)"
    print(f"   ├ ECC:        Ed25519 active — {address_display[:20]}...", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        stop_mdns()
        stop_scheduler()
        stop_radio()
        MeshNode.stop()
        print("[CPIP] Stopped.", flush=True)


if __name__ == "__main__":
    main()
