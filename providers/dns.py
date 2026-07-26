from __future__ import annotations

import sys
import urllib.request
from typing import Any

from providers.base import BaseProvider, ProviderType
from providers.registry import ProviderRegistry


class DNSProvider(BaseProvider):
    TYPE = ProviderType.DNS
    NAME = "dns_base"
    SERVER_URL = ""
    TIMEOUT = 5


    @classmethod
    def is_available(cls) -> bool:
        return bool(cls.SERVER_URL)


    @classmethod
    def resolve(cls, hostname: str, record_type: str = "A") -> list[str]:
        raise NotImplementedError


    @classmethod
    def doh_resolve(cls, hostname: str) -> list[str]:
        if not cls.SERVER_URL:
            return []
        url = cls.SERVER_URL.format(hostname=hostname)
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=cls.TIMEOUT) as resp:
                data = resp.read().decode()
                return cls._parse_doh_response(data)
        except Exception:
            return []


    @classmethod
    def _parse_doh_response(cls, data: str) -> list[str]:
        return []


    @classmethod
    def get_info(cls) -> dict[str, Any]:
        info = super().get_info()
        info.update({
            "server_url": cls.SERVER_URL,
            "timeout": cls.TIMEOUT,
        })
        return info


class CloudflareDoHProvider(DNSProvider):
    NAME = "cloudflare"
    SERVER_URL = "https://cloudflare-dns.com/dns-query?name={hostname}&type=A"


    @classmethod
    def _parse_doh_response(cls, data: str) -> list[str]:
        import json
        try:
            result = json.loads(data)
            return [a.get("data", "") for a in result.get("Answer", []) if a.get("type") == 1]
        except Exception:
            return []


class GoogleDoHProvider(DNSProvider):
    NAME = "google"
    SERVER_URL = "https://dns.google/resolve?name={hostname}&type=A"


    @classmethod
    def _parse_doh_response(cls, data: str) -> list[str]:
        import json
        try:
            result = json.loads(data)
            return [a.get("data", "") for a in result.get("Answer", []) if a.get("type") == 1]
        except Exception:
            return []


# ── Register all DNS providers ──────────────────────────────────────────

DNS_PROVIDERS: dict[str, type[DNSProvider]] = {}

def register_dns_provider(name: str, provider_cls: type[DNSProvider]) -> None:
    DNS_PROVIDERS[name] = provider_cls
    ProviderRegistry.register(provider_cls)


register_dns_provider("cloudflare", CloudflareDoHProvider)
register_dns_provider("google", GoogleDoHProvider)
