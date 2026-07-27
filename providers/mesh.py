from __future__ import annotations

import os
import sys
from typing import Any, Callable

from providers.base import BaseProvider, ProviderType
from providers.registry import ProviderRegistry

PQ_MESH_ENABLED = os.environ.get("CPIP_PQ_MESH", "1") == "1"
PQ_MESH_KEM = os.environ.get("CPIP_PQ_MESH_KEM", "ml_kem_768")
PQ_MESH_SIG = os.environ.get("CPIP_PQ_MESH_SIG", "dilithium2")


class PQMesh:
    """Post-quantum mesh protocol using hybrid KEM + signing."""

    NAME = "pq_mesh"
    VERSION = "6.0.3"
    ENABLED = PQ_MESH_ENABLED
    KEM_ALGORITHM = PQ_MESH_KEM
    SIG_ALGORITHM = PQ_MESH_SIG

    @classmethod
    def is_available(cls) -> bool:
        return cls.ENABLED

    @classmethod
    def get_kem(cls) -> str:
        return cls.KEM_ALGORITHM

    @classmethod
    def get_sig(cls) -> str:
        return cls.SIG_ALGORITHM

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": cls.ENABLED,
            "kem": cls.KEM_ALGORITHM,
            "sig": cls.SIG_ALGORITHM,
            "pq_mesh_active": cls.ENABLED,
        }


class MeshTransportProvider(BaseProvider):
    TYPE = ProviderType.MESH_TRANSPORT
    NAME = "mesh_transport_base"
    TRANSPORT_TYPE = "base"


    @classmethod
    def is_available(cls) -> bool:
        return False


    @classmethod
    def can_reach(cls, dst_pot: str) -> bool:
        return False


    @classmethod
    def send(cls, data: bytes, dst_pot: str = "") -> bool:
        raise NotImplementedError


    @classmethod
    def get_bandwidth(cls) -> int:
        return 0


    @classmethod
    def get_info(cls) -> dict[str, Any]:
        info = super().get_info()
        info.update({
            "transport_type": cls.TRANSPORT_TYPE,
            "bandwidth_bps": cls.get_bandwidth(),
        })
        return info


class BondedMeshTransport:
    """Aggregates all registered mesh transport providers for bonded delivery."""

    @classmethod
    def get_send_fns(cls, dst_pot: str = "") -> dict[str, Callable]:
        fns: dict[str, Callable] = {}
        for provider in ProviderRegistry.list_available(ProviderType.MESH_TRANSPORT):
            if provider.can_reach(dst_pot):
                link_id = f"{provider.TRANSPORT_TYPE}:{provider.NAME}"
                fns[link_id] = lambda data, p=provider, d=dst_pot: p.send(data, d)
        return fns


    @classmethod
    def send_fragment(cls, link_id: str, data: bytes) -> None:
        fns = cls.get_send_fns()
        fn = fns.get(link_id)
        if fn:
            try:
                fn(data)
            except Exception:
                pass
