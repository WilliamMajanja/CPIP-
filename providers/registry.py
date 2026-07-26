from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from providers.base import BaseProvider, ProviderType


class ProviderRegistry:
    _providers: dict[tuple[str, str], type[BaseProvider]] = {}


    @classmethod
    def register(cls, provider_cls: type[BaseProvider]) -> type[BaseProvider]:
        key = (provider_cls.TYPE.value if hasattr(provider_cls.TYPE, 'value') else str(provider_cls.TYPE),
               provider_cls.NAME)
        cls._providers[key] = provider_cls
        return provider_cls


    @classmethod
    def get(cls, ptype: str | ProviderType, name: str) -> type[BaseProvider]:
        type_str = ptype.value if hasattr(ptype, 'value') else str(ptype)
        key = (type_str, name)
        if key not in cls._providers:
            available = [f"{t}/{n}" for (t, n) in cls._providers]
            raise KeyError(f"Provider '{type_str}/{name}' not found. Available: {', '.join(available) or 'none'}")
        return cls._providers[key]


    @classmethod
    def list(cls, ptype: str | ProviderType | None = None) -> list[type[BaseProvider]]:
        if ptype is None:
            return list(cls._providers.values())
        type_str = ptype.value if hasattr(ptype, 'value') else str(ptype)
        return [p for (t, n), p in cls._providers.items() if t == type_str]


    @classmethod
    def list_available(cls, ptype: str | ProviderType | None = None) -> list[type[BaseProvider]]:
        return [p for p in cls.list(ptype) if p.is_available()]


    @classmethod
    def get_info(cls, ptype: str | ProviderType | None = None) -> list[dict[str, Any]]:
        return [p.get_info() for p in cls.list(ptype)]
