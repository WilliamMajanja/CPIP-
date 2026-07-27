from __future__ import annotations

import os
import sys
from typing import Any

from providers.base import BaseProvider, ProviderType
from providers.registry import ProviderRegistry


class KEMProvider(BaseProvider):
    TYPE = ProviderType.KEM
    NAME = "kem_base"
    ALGORITHM = "base"
    PUBLIC_KEY_SIZE = 0
    SECRET_KEY_SIZE = 0
    CIPHERTEXT_SIZE = 0
    SHARED_KEY_SIZE = 32


    @classmethod
    def is_available(cls) -> bool:
        return cls._implementation_available()


    @classmethod
    def _implementation_available(cls) -> bool:
        return False


    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        raise NotImplementedError


    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        raise NotImplementedError


    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError


    @classmethod
    def encrypt(cls, public_key: bytes) -> tuple[bytes, bytes]:
        return cls.encapsulate(public_key)


    @classmethod
    def decrypt(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        return cls.decapsulate(secret_key, ciphertext)


    @classmethod
    def get_info(cls) -> dict[str, Any]:
        info = super().get_info()
        info.update({
            "algorithm": cls.ALGORITHM,
            "public_key_size": cls.PUBLIC_KEY_SIZE,
            "secret_key_size": cls.SECRET_KEY_SIZE,
            "ciphertext_size": cls.CIPHERTEXT_SIZE,
            "shared_key_size": cls.SHARED_KEY_SIZE,
        })
        return info


# ── Legacy PQCKEM compatibility layer ────────────────────────────────

# These will be imported from server.py and wrapped as KEMProvider instances.
# The PQCKEM base class and all subclasses remain in server.py for backward
# compatibility. This module provides the provider-wrapped equivalents.

PQC_KEM_REGISTRY: dict[str, type[KEMProvider]] = {}


def register_kem_provider(name: str, provider_cls: type[KEMProvider]) -> None:
    PQC_KEM_REGISTRY[name] = provider_cls
    ProviderRegistry.register(provider_cls)


def get_pqc_kem(algorithm: str) -> type[KEMProvider]:
    if algorithm not in PQC_KEM_REGISTRY:
        raise ValueError(
            f"Unknown PQC KEM algorithm: {algorithm}. "
            f"Available: {list(PQC_KEM_REGISTRY.keys())}"
        )
    cls = PQC_KEM_REGISTRY[algorithm]
    if not cls.is_available():
        raise RuntimeError(f"PQC KEM {algorithm} not available")
    return cls


def list_pqc_kems() -> dict[str, dict[str, Any]]:
    result = {}
    for name, cls in PQC_KEM_REGISTRY.items():
        result[name] = cls.get_info()
    return result


# ── Kyber adapter as a provider ──────────────────────────────────────

class Kyber(KEMProvider):
    NAME = "ml_kem_768"
    ALGORITHM = "ml_kem_768"
    N = 256
    K = 3
    Q = 3329
    ETA1 = 2
    ETA2 = 2
    DU = 10
    DV = 4
    _backend = None


    @classmethod
    def _get_backend(cls):
        if cls._backend is not None:
            return cls._backend
        try:
            from inf1del_kyber import Inf1delKyber
            Inf1delKyber.keygen()
            cls._backend = "inf1del"
            return cls._backend
        except Exception:
            pass
        try:
            from server import _PQCRYPTO_AVAILABLE
            if _PQCRYPTO_AVAILABLE:
                cls._backend = "pqcrypto"
                return cls._backend
        except Exception:
            pass
        raise RuntimeError("No ML-KEM-768 backend available")


    @classmethod
    def _implementation_available(cls) -> bool:
        try:
            cls._get_backend()
            return True
        except Exception:
            return False


    @classmethod
    def is_available(cls) -> bool:
        return cls._implementation_available()


    @classmethod
    def keygen(cls) -> tuple:
        backend = cls._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.keygen()
        elif backend == "pqcrypto":
            from server import MLKEM768
            return MLKEM768.generate_keypair()
        raise RuntimeError("No Kyber backend")


    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        return cls.keygen()


    @classmethod
    def encaps(cls, public_key: bytes) -> tuple:
        backend = cls._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.encaps(public_key)
        elif backend == "pqcrypto":
            from server import MLKEM768
            return MLKEM768.encapsulate(public_key)
        raise RuntimeError("No Kyber backend")


    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        return cls.encaps(public_key)


    @classmethod
    def decaps(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        backend = cls._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.decaps(secret_key, ciphertext)
        elif backend == "pqcrypto":
            from server import MLKEM768
            return MLKEM768.decapsulate(secret_key, ciphertext)
        raise RuntimeError("No Kyber backend")


    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        return cls.decaps(secret_key, ciphertext)


register_kem_provider("ml_kem_768", Kyber)


# ── Make Kyber available at module level like before ──────────────────
def keygen() -> tuple:
    return Kyber.keygen()


def encaps(public_key: bytes) -> tuple:
    return Kyber.encaps(public_key)


def decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    return Kyber.decaps(secret_key, ciphertext)


PQC_IDENTITY_MAILBOX = os.environ.get("CPIP_PQC_IDENTITY", "mailbox")
PQC_KEM_ALGORITHM = os.environ.get("CPIP_PQC_KEM", "ml_kem_768")


class PQCIdentity:
    """Quantum-resistant identity using PQC key encapsulation."""

    NAME = "pqc_identity"
    VERSION = "6.0.3"
    KEM_ALGORITHM = PQC_KEM_ALGORITHM
    MAILBOX = PQC_IDENTITY_MAILBOX

    _identity_key: bytes | None = None
    _identity_cert: bytes | None = None

    @classmethod
    def is_available(cls) -> bool:
        try:
            Kyber.is_available()
            return True
        except Exception:
            return False

    @classmethod
    def generate_identity(cls) -> tuple[bytes, bytes]:
        pub, sec = Kyber.generate_keypair()
        cls._identity_key = sec
        cls._identity_cert = pub
        return pub, sec

    @classmethod
    def get_kem_algorithm(cls) -> str:
        return cls.KEM_ALGORITHM

    @classmethod
    def get_mailbox(cls) -> str:
        return cls.MAILBOX

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "kem_algorithm": cls.KEM_ALGORITHM,
            "mailbox": cls.MAILBOX,
            "identity_present": cls._identity_key is not None,
            "available": cls.is_available(),
        }
