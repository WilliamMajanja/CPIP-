from __future__ import annotations

import sys
from typing import Any, Callable

from providers.base import BaseProvider, ProviderType
from providers.registry import ProviderRegistry


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
