from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProviderType(Enum):
    KEM = "kem"
    MESH_TRANSPORT = "mesh_transport"
    DNS = "dns"
    COVERT = "covert"
    NOTIFICATION = "notification"
    STORAGE = "storage"
    RADIO = "radio"
    NTP = "ntp"
    WEBHOOK = "webhook"
    CELLULAR = "cellular"
    SENSOR = "sensor"
    SDR = "sdr"
    SCORER = "scorer"
    HARDWARE = "hardware"
    SS7 = "ss7"
    MODEM = "modem"
    POWER = "power"
    CIRCUMVENTION = "circumvention"
    HYGIENE = "hygiene"
    INTELLIGENCE = "intelligence"
    EVIDENCE = "evidence"
    DECEPTION = "deception"
    SECURITY = "security"


    @classmethod
    def from_str(cls, s: str) -> ProviderType:
        for t in cls:
            if t.value == s:
                return t
            if t.name.lower() == s.lower():
                return t
        raise ValueError(f"Unknown provider type: {s}")


@dataclass
class ProviderConfig:
    type: ProviderType
    name: str
    priority: int = 100
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)


    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "name": self.name,
            "priority": self.priority,
            "enabled": self.enabled,
            "options": dict(self.options),
        }


class BaseProvider(ABC):
    TYPE: ProviderType
    NAME: str = "base"
    VERSION: str = "1.0.0"
    CONFIG: ProviderConfig | None = None


    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        ...


    @classmethod
    def configure(cls, **kwargs) -> None:
        if cls.CONFIG is None:
            cls.CONFIG = ProviderConfig(type=cls.TYPE, name=cls.NAME)
        for k, v in kwargs.items():
            if k in ("type", "name", "priority", "enabled"):
                setattr(cls.CONFIG, k, v)
            else:
                cls.CONFIG.options[k] = v


    @classmethod
    def get_info(cls) -> dict[str, Any]:
        return {
            "type": cls.TYPE.value if isinstance(cls.TYPE, ProviderType) else str(cls.TYPE),
            "name": cls.NAME,
            "version": cls.VERSION,
            "available": cls.is_available(),
            "config": cls.CONFIG.to_dict() if cls.CONFIG else None,
        }


    @classmethod
    def validate_config(cls, **kwargs) -> list[str]:
        errors: list[str] = []
        return errors
