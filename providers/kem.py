from __future__ import annotations

import os
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
    _register_dsa_ml_kems()
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
    _register_dsa_ml_kems()
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
            from server import DSA_ML_KEM
            backend = DSA_ML_KEM(768)
            backend.keygen()  # selects the configured backend and verifies it
            cls._backend = backend
            return backend
        except Exception:
            cls._backend = None
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
        return cls._get_backend().keygen()


    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        return cls.keygen()


    @classmethod
    def encaps(cls, public_key: bytes) -> tuple:
        return cls._get_backend().encapsulate(public_key)


    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        return cls.encaps(public_key)


    @classmethod
    def decaps(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        return cls._get_backend().decapsulate(secret_key, ciphertext)


    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        return cls.decaps(secret_key, ciphertext)


# ── DSA-ML-KEM: All standard sizes ──────────────────────
# Supports standard 512/768/1024 sizes plus experimental 1nf1D3L ranks 2048/4096.
# Supports NumPy-accelerated, pqcrypto, and standard-library-only backends.

_SUPPORTED_KEM_SIZES = (512, 768, 1024, 2048, 4096)
_STANDARD_KEM_SIZES = (512, 768, 1024)
_ML_KEM_SIZE = int(os.environ.get("CPIP_ML_KEM_SIZE", "768"))
if _ML_KEM_SIZE not in _SUPPORTED_KEM_SIZES:
    _ML_KEM_SIZE = 768

# DSA_ML_KEM lives in server.py; resolve it lazily so that providers.kem can
# be imported while server.py is still mid-initialization (server imports
# providers.kem near the top of the file). server.py registers the wrapped
# DSA-ML-KEM providers itself once it finishes importing.
_DSA_ML_KEM_CLS: type | None = None
_DSML_KEM = None
_dsa_kems_registered = False


def _dsa_ml_kem_class() -> type:
    """Resolve the DSA_ML_KEM class from server.py on first use.

    Deferred to call time (not module import time) to avoid the circular
    import: server.py imports providers.kem before DSA_ML_KEM is defined.
    """
    global _DSA_ML_KEM_CLS
    if _DSA_ML_KEM_CLS is None:
        from server import DSA_ML_KEM
        _DSA_ML_KEM_CLS = DSA_ML_KEM
    return _DSA_ML_KEM_CLS


def _register_dsa_ml_kems() -> None:
    """Register the three DSA-ML-KEM sizes as proper KEMProvider classes.

    Each size wraps a DSA_ML_KEM instance so it conforms to the KEMProvider
    contract (TYPE/NAME + classmethods). Idempotent: server.py registers these
    itself once fully imported, so this is a no-op in that path and a safety
    net when providers.kem is imported standalone.
    """
    global _dsa_kems_registered
    if _dsa_kems_registered:
        return
    try:
        cls = _dsa_ml_kem_class()
    except Exception:
        # The provider/CLI can use the raw KEMs without importing the full
        # server (and its cryptography dependency) in stdlib-only contexts.
        try:
            from pure_mlkem import PurePythonMLKEM
        except Exception:
            return
        for size in _SUPPORTED_KEM_SIZES:
            name = f"ml_kem_{size}" if size in _STANDARD_KEM_SIZES else f"1nf1d3l_kem_{size}"
            if name in PQC_KEM_REGISTRY:
                continue
            inst = PurePythonMLKEM(size)
            provider_cls = type(
                f"KEM_{name}",
                (KEMProvider,),
                {
                    "NAME": name,
                    "ALGORITHM": name,
                    "PUBLIC_KEY_SIZE": inst.public_key_size,
                    "SECRET_KEY_SIZE": inst.secret_key_size,
                    "CIPHERTEXT_SIZE": inst.ciphertext_size,
                    "SHARED_KEY_SIZE": inst.shared_key_size,
                    "_kem_instance": inst,
                    "_implementation_available": classmethod(lambda c: True),
                    "generate_keypair": classmethod(lambda c: c._kem_instance.keygen()),
                    "encapsulate": classmethod(lambda c, pk: c._kem_instance.encapsulate(pk)),
                    "decapsulate": classmethod(lambda c, sk, ct: c._kem_instance.decapsulate(sk, ct)),
                },
            )
            register_kem_provider(name, provider_cls)
        _dsa_kems_registered = True
        return
    for size in _SUPPORTED_KEM_SIZES:
        name = f"ml_kem_{size}" if size in _STANDARD_KEM_SIZES else f"1nf1d3l_kem_{size}"
        if name in PQC_KEM_REGISTRY:
            continue
        inst = cls(size)
        provider_cls = type(
            f"KEM_{name}",
            (KEMProvider,),
            {
                "NAME": name,
                "ALGORITHM": inst.algorithm,
                "PUBLIC_KEY_SIZE": inst.public_key_size,
                "SECRET_KEY_SIZE": inst.secret_key_size,
                "CIPHERTEXT_SIZE": inst.ciphertext_size,
                "SHARED_KEY_SIZE": inst.shared_key_size,
                "_kem_instance": inst,
                "_implementation_available": classmethod(lambda c: True),
                "generate_keypair": classmethod(lambda c: c._kem_instance.keygen()),
                "encapsulate": classmethod(lambda c, pk: c._kem_instance.encapsulate(pk)),
                "decapsulate": classmethod(lambda c, sk, ct: c._kem_instance.decapsulate(sk, ct)),
            },
        )
        register_kem_provider(name, provider_cls)
    _dsa_kems_registered = True


# ── Module-level DSA-ML-KEM functions ──────────────────

def keygen(size: int = 768) -> tuple:
    _register_dsa_ml_kems()
    return _dsa_ml_kem_class()(size).keygen()


def encaps(public_key: bytes, size: int = 768) -> tuple:
    _register_dsa_ml_kems()
    return _dsa_ml_kem_class()(size).encapsulate(public_key)


def decaps(secret_key: bytes, ciphertext: bytes, size: int = 768) -> bytes:
    _register_dsa_ml_kems()
    return _dsa_ml_kem_class()(size).decapsulate(secret_key, ciphertext)


# ── DSA-SLH-DSA (SPHINCS+) ──────────────────────────────
# NIST FIPS 205 — Stateless hash-based signatures
# 1nf1D3L backend: domain-separated with "1NF1D3L-SLH-V1" tag

SLH_DSA_VARIANTS = {
    "slh_dsa_sha2_128f_simple": "SLH-DSA-SHA2-128f (1nf1D3L)",
    "slh_dsa_sha2_128s_simple": "SLH-DSA-SHA2-128s (1nf1D3L)",
    "slh_dsa_sha2_192f_simple": "SLH-DSA-SHA2-192f (1nf1D3L)",
    "slh_dsa_sha2_192s_simple": "SLH-DSA-SHA2-192s (1nf1D3L)",
    "slh_dsa_sha2_256f_simple": "SLH-DSA-SHA2-256f (1nf1D3L)",
    "slh_dsa_sha2_256s_simple": "SLH-DSA-SHA2-256s (1nf1D3L)",
    "slh_dsa_shake_128f_simple": "SLH-DSA-SHAKE-128f (1nf1D3L)",
    "slh_dsa_shake_128s_simple": "SLH-DSA-SHAKE-128s (1nf1D3L)",
    "slh_dsa_shake_192f_simple": "SLH-DSA-SHAKE-192f (1nf1D3L)",
    "slh_dsa_shake_192s_simple": "SLH-DSA-SHAKE-192s (1nf1D3L)",
    "slh_dsa_shake_256f_simple": "SLH-DSA-SHAKE-256f (1nf1D3L)",
    "slh_dsa_shake_256s_simple": "SLH-DSA-SHAKE-256s (1nf1D3L)",
}


def _get_inf1del_slh():
    """Lazy-import Inf1delSLH from inf1del_kyber.py."""
    from inf1del_kyber import Inf1delSLH
    return Inf1delSLH


def get_slh_dsa(variant: str = None, recipe: str = "espresso"):
    """Get an Inf1delSLH instance for the specified variant."""
    if variant is None:
        variant = PQC_SIGN_ALGORITHM
    Inf1delSLH = _get_inf1del_slh()
    return Inf1delSLH(variant, recipe)


# ── DSA-ML-DSA (Dilithium) ──────────────────────────────
# NIST FIPS 204 — Module-lattice signatures
ML_DSA_VARIANTS = {
    "ml_dsa_44": "ML-DSA-44 (FIPS 204, Level 2)",
    "ml_dsa_65": "ML-DSA-65 (FIPS 204, Level 3)",
    "ml_dsa_87": "ML-DSA-87 (FIPS 204, Level 5)",
}


# ── PQC-SUCI identity (RFC-0003) ──────────────────────────────────────
# CPIP_PQC_IDENTITY mode: 0 = ECDH-only fallback, 1 = ML-KEM-only,
# hybrid = ECDH + ML-KEM (default per spec).
PQC_IDENTITY_MODE = os.environ.get("CPIP_PQC_IDENTITY", "hybrid").strip().lower()
if PQC_IDENTITY_MODE not in ("0", "1", "hybrid"):
    PQC_IDENTITY_MODE = "hybrid"
PQC_KEM_ALGORITHM = os.environ.get("CPIP_PQC_KEM", "ml_kem_768")
PQC_SIGN_ALGORITHM = os.environ.get("CPIP_PQC_SIGN", "slh_dsa_sha2_256f_simple")

MODE_NAMES = {
    "0": "ECDH-only (pre-v6 fallback)",
    "1": "ML-KEM-only (quantum-resistant)",
    "hybrid": "ECDH + ML-KEM hybrid",
}

SIGN_MODE_NAMES = {
    "slh_dsa_sha2_256f_simple": "SLH-DSA-SHA2-256f (1nf1D3L)",
    "ml_dsa_65": "ML-DSA-65 (1nf1D3L)",
}


class PQCIdentity:
    """Quantum-resistant subscriber identity (RFC-0003).

    Conceals SUPI as SUCI using an ephemeral KEM per registration, with
    hybrid ECDH+ML-KEM (mode=hybrid), ML-KEM-only (mode=1) or ECDH-only
    (mode=0) fallback for pre-v6 peers.
    Supports DSA-ML-KEM at all standard sizes and DSA-SLH-DSA/ML-DSA signatures.
    """

    NAME = "pqc_identity"
    VERSION = "7.0.0"
    KEM_ALGORITHM = PQC_KEM_ALGORITHM
    MODE = PQC_IDENTITY_MODE

    _identity_key: bytes | None = None
    _identity_cert: bytes | None = None
    _ecdh_priv: Any = None
    _ecdh_pub_pem: bytes | None = None

    @classmethod
    def is_available(cls) -> bool:
        if cls.MODE == "0":
            return True  # ECDH-only always available
        try:
            cls._kem_keypair(cls._select_kem())
            return True
        except Exception:
            return False

    @classmethod
    def _select_kem(cls):
        _register_dsa_ml_kems()
        if cls.KEM_ALGORITHM not in PQC_KEM_REGISTRY:
            try:
                size = int(cls.KEM_ALGORITHM.rsplit("_", 1)[1])
            except (ValueError, IndexError):
                size = _ML_KEM_SIZE
            if size in _SUPPORTED_KEM_SIZES and cls.KEM_ALGORITHM in (
                f"ml_kem_{size}", f"1nf1d3l_kem_{size}"
            ):
                return _dsa_ml_kem_class()(size)
            raise ValueError(f"Unknown configured PQC KEM: {cls.KEM_ALGORITHM}")
        return PQC_KEM_REGISTRY[cls.KEM_ALGORITHM]

    @classmethod
    def _kem_keypair(cls, kem):
        """Generate a keypair on either a KEMProvider class or a raw KEM
        instance — registry entries use generate_keypair(), low-level
        backends (DSA_ML_KEM, 1nf1D3L) use keygen()."""
        gen = getattr(kem, "generate_keypair", None)
        if callable(gen):
            return gen()
        return kem.keygen()

    @classmethod
    def _derive_ecdh(cls) -> tuple[Any, bytes]:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub_pem

    @classmethod
    def generate_identity(cls) -> dict[str, bytes]:
        """Generate identity material: PQC KEM keypair (+ ECDH key)."""
        result: dict[str, bytes] = {}
        if cls.MODE != "0":
            kem = cls._select_kem()
            pub, sec = cls._kem_keypair(kem)
            cls._identity_key = sec
            cls._identity_cert = pub
            result["kem_algorithm"] = cls.KEM_ALGORITHM.encode()
            result["pubkey"] = pub
            result["seckey"] = sec
        if cls.MODE != "1":
            cls._ecdh_priv, cls._ecdh_pub_pem = cls._derive_ecdh()
            result["ecdh_pubkey"] = cls._ecdh_pub_pem
        return result

    @classmethod
    def _suci_keystream(cls, ss: bytes, length: int) -> bytes:
        """Counter-mode keystream derived only from the shared secret."""
        import hashlib
        out = b""
        counter = 0
        while len(out) < length:
            out += hashlib.sha256(ss + counter.to_bytes(4, "big")).digest()
            counter += 1
        return out[:length]

    @classmethod
    def conceal_supi(cls, supi: str, kem_pub: bytes | None = None) -> dict[str, Any]:
        """Encrypt a SUPI using a fresh KEM secret and authenticated encryption.

        ``suci`` contains salt || nonce || AES-GCM ciphertext. No public-key
        derived fallback is allowed: absent recipient key material is an error.
        """
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        if not isinstance(supi, str) or not supi:
            return {"error": "SUPI must be a non-empty string"}
        if cls.MODE == "0":
            return {"error": "ECDH-only SUCI is not supported by this API; configure hybrid or ML-KEM mode"}
        kem = cls._select_kem()
        recipient = kem_pub or cls._identity_cert
        if not recipient:
            return {"error": "No recipient ML-KEM public key; generate or provide a key first"}
        try:
            kem_ct, shared_secret = kem.encapsulate(recipient)
            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                       info=b"cpip-pqc-suci-aesgcm-v1").derive(shared_secret)
            encrypted = AESGCM(key).encrypt(nonce, supi.encode("utf-8"), b"cpip-suci-v1")
        except Exception as exc:
            return {"error": f"SUCI encryption failed: {exc}"}
        bundle = salt + nonce + encrypted
        return {
            "mode": cls.MODE,
            "kem_algorithm": cls.KEM_ALGORITHM,
            "ciphertext": kem_ct.hex(),
            "suci": bundle.hex(),
            "concealed_supi": bundle.hex(),
        }

    @classmethod
    def reveal_suci(cls, suci_hex: str, ct_hex: str | None = None) -> dict[str, Any]:
        """Reverse conceal_supi — recover SUPI from a SUCI bundle."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        try:
            concealed = bytes.fromhex(suci_hex)
            kem_ct = bytes.fromhex(ct_hex or "")
        except ValueError:
            return {"error": "invalid suci hex"}
        if len(concealed) < 44 or not kem_ct or not cls._identity_key:
            return {"error": "SUCI bundle, KEM ciphertext, or recipient private key is missing"}
        try:
            shared_secret = cls._select_kem().decapsulate(cls._identity_key, kem_ct)
            salt, nonce, encrypted = concealed[:16], concealed[16:28], concealed[28:]
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                       info=b"cpip-pqc-suci-aesgcm-v1").derive(shared_secret)
            supi = AESGCM(key).decrypt(nonce, encrypted, b"cpip-suci-v1").decode("utf-8")
            return {"suci_recovered": True, "supi": supi}
        except (InvalidTag, UnicodeDecodeError):
            return {"error": "SUCI authentication failed"}
        except Exception as exc:
            return {"error": f"SUCI decryption failed: {exc}"}

    @classmethod
    def handshake(cls, peer_pub: bytes | None = None) -> dict[str, Any]:
        """Hybrid ECDH+ML-KEM handshake material (RFC-0003/RFC-0019)."""
        result: dict[str, Any] = {"mode": cls.MODE}
        secrets_material = []
        if cls.MODE != "0":
            kem = cls._select_kem()
            result["kem_algorithm"] = cls.KEM_ALGORITHM
            if peer_pub:
                try:
                    ct, secret = kem.encapsulate(peer_pub)
                    result["kem_ciphertext"] = ct.hex()
                    secrets_material.append(secret)
                except Exception as exc:
                    return {"error": f"Invalid peer KEM public key: {exc}"}
            else:
                pub, sec = cls._kem_keypair(kem)
                result["kem_pubkey"] = pub.hex()
                cls._identity_key = sec
                cls._identity_cert = pub
        if cls.MODE != "1":
            priv, pub_pem = cls._derive_ecdh()
            result["ecdh_pubkey_pem"] = pub_pem.decode()
            if peer_pub:
                result["note"] = "Provide the peer ECDH public key separately to complete hybrid agreement"
        result["identity_present"] = cls._identity_key is not None
        if secrets_material:
            import hashlib
            result["session_id"] = hashlib.sha256(b"".join(secrets_material)).hexdigest()[:16]
        return result

    @classmethod
    def rotate(cls) -> dict[str, Any]:
        """Rotate identity keys (RFC-0003 CLI: pqc-rotate)."""
        material = cls.generate_identity()
        cls._identity_key = material.get("seckey")
        cls._identity_cert = material.get("pubkey")
        cls._ecdh_pub_pem = material.get("ecdh_pubkey")
        return {
            "status": "keys_rotated",
            "mode": cls.MODE,
            "kem_algorithm": cls.KEM_ALGORITHM,
            "sign_algorithm": PQC_SIGN_ALGORITHM,
            "identity_present": cls._identity_key is not None,
        }

    @classmethod
    def get_kem_algorithm(cls) -> str:
        return cls.KEM_ALGORITHM

    @classmethod
    def get_mailbox(cls) -> str:
        return cls.MAILBOX if hasattr(cls, "MAILBOX") else ""

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        try:
            size = int(cls.KEM_ALGORITHM.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            size = _ML_KEM_SIZE
        preference = os.environ.get("CPIP_ML_KEM_BACKEND", "auto").strip().lower()
        backend = "unavailable"
        cached_backend = None
        pqcrypto_available = False
        try:
            from server import _ML_KEM_BACKENDS, _PQCRYPTO_AVAILABLE
            cached_backend = _ML_KEM_BACKENDS.get(size)
            pqcrypto_available = _PQCRYPTO_AVAILABLE and size in _STANDARD_KEM_SIZES
        except Exception:
            pass
        if cached_backend:
            backend = cached_backend
        else:
            backend = f"{preference} (not selected)"
        if preference in ("stdlib", "python", "pure-python", "auto"):
            available = True  # bundled standard-library fallback
        elif preference in ("numpy", "inf1del"):
            try:
                import numpy  # noqa: F401
                available = True
            except ImportError:
                available = False
        elif preference == "pqcrypto":
            available = pqcrypto_available
        else:
            available = False
        return {
            "mode": cls.MODE,
            "mode_name": MODE_NAMES.get(cls.MODE, cls.MODE),
            "kem_algorithm": cls.KEM_ALGORITHM,
            "identity_present": cls._identity_key is not None,
            "ecdh_present": cls._ecdh_pub_pem is not None,
            "sign_algorithm": PQC_SIGN_ALGORITHM,
            "ml_kem_size": size,
            "available": available,
            "backend": backend,
            "backend_preference": preference,
            "supported_sizes": [512, 768, 1024, 2048, 4096],
            "experimental_sizes": [2048, 4096],
        }
