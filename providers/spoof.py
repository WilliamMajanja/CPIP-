"""IP Spoofing / Proxy Rotation Module for CPIP
Provides source IP rotation, SOCKS5/HTTP proxy chaining, and
interface rotation for outbound connections to evade IP-based
blacklisting (e.g., Sucuri, Cloudflare, etc.).

Environment variables:
  CPIP_SPOOF=1                        Enable IP spoofing/rotation
  CPIP_SPOOF_MODE=tor|proxy|srcip|iface  Rotation mode
  CPIP_PROXY_LIST=socks5://...        Comma-separated proxy URLs
  CPIP_PROXY_FILE=/path/to/proxies.txt  File with proxies (one per line)
  CPIP_PROXY_ROTATE=request|minute|hour  Rotation interval
  CPIP_SPOOF_INTERFACES=eth0,wlan0,tun0  Source interfaces to bind
  CPIP_SPOOF_SOURCE_IPS=10.0.0.1,...   Source IPs to cycle through
  CPIP_TOR_PROXY=socks5://127.0.0.1:9050  Tor SOCKS5 proxy
"""

import ipaddress
import os
import random
import socket
import ssl
import struct
import threading
import time
import urllib.request
from typing import Optional
from urllib.parse import urlparse


SPOOF_ENABLED = os.environ.get("CPIP_SPOOF", "0") == "1"
SPOOF_MODE = os.environ.get("CPIP_SPOOF_MODE", "tor")
PROXY_LIST_ENV = os.environ.get("CPIP_PROXY_LIST", "")
PROXY_FILE = os.environ.get("CPIP_PROXY_FILE", "")
PROXY_ROTATE_INTERVAL = os.environ.get("CPIP_PROXY_ROTATE", "request")
SPOOF_INTERFACES = os.environ.get("CPIP_SPOOF_INTERFACES", "").split(",")
SPOOF_SOURCE_IPS = os.environ.get("CPIP_SPOOF_SOURCE_IPS", "").split(",")
TOR_PROXY = os.environ.get("CPIP_TOR_PROXY", "socks5://127.0.0.1:9050")


class ProxyManager:
    _instance = None
    _lock = threading.Lock()

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
        self._proxies = []
        self._tor_available = False
        self._current_idx = 0
        self._load_proxies()
        self._check_tor()

    def _load_proxies(self):
        proxies = []
        if PROXY_LIST_ENV:
            for p in PROXY_LIST_ENV.split(","):
                p = p.strip()
                if p:
                    proxies.append(p)
        if PROXY_FILE:
            try:
                with open(PROXY_FILE) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            proxies.append(line)
            except (OSError, IOError):
                pass
        self._proxies = proxies

    def _check_tor(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            parsed = urlparse(TOR_PROXY)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 9050
            s.connect((host, port))
            s.close()
            self._tor_available = True
        except (socket.error, OSError):
            self._tor_available = False

    @property
    def tor_available(self):
        return self._tor_available

    @property
    def proxy_count(self):
        return len(self._proxies)

    def get_proxy(self):
        if not self._proxies:
            return None
        if PROXY_ROTATE_INTERVAL == "request":
            self._current_idx = (self._current_idx + 1) % len(self._proxies)
            return self._proxies[self._current_idx]
        return random.choice(self._proxies)

    def wrap_urllib(self):
        """Patch urllib to route through proxy chain"""
        proxy = self.get_proxy()
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy,
                "https": proxy,
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
        elif self._tor_available:
            proxy_handler = urllib.request.ProxyHandler({
                "http": TOR_PROXY,
                "https": TOR_PROXY,
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

    def socks5_connect(self, host, port, timeout=10):
        """Connect through SOCKS5 proxy (Tor or configured proxy)"""
        proxy_url = self.get_proxy() or TOR_PROXY if self._tor_available else None
        if not proxy_url:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            return s

        parsed = urlparse(proxy_url)
        proxy_host = parsed.hostname or "127.0.0.1"
        proxy_port = parsed.port or 9050

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_host, proxy_port))

        s.sendall(struct.pack("!BBB", 0x05, 0x01, 0x00))
        resp = s.recv(2)
        if resp != b"\x05\x00":
            s.close()
            raise ConnectionError("SOCKS5 auth method negotiation failed")

        if ":" in host:
            addr_type = 0x04
            addr_bytes = socket.inet_pton(socket.AF_INET6, host)
        else:
            addr_type = 0x01
            addr_bytes = socket.inet_aton(host)

        req = struct.pack("!BBB", 0x05, 0x01, 0x00) + struct.pack("!B", addr_type) + addr_bytes + struct.pack("!H", port)
        s.sendall(req)
        resp = s.recv(4)
        if len(resp) < 2 or resp[1] != 0x00:
            s.close()
            raise ConnectionError(f"SOCKS5 connection failed: {resp[1] if len(resp) > 1 else 'unknown'}")

        addr_len = {0x01: 4, 0x04: 16}.get(resp[3], 0)
        if addr_len:
            s.recv(addr_len + 2)
        return s


class IPRotator:
    _instance = None
    _lock = threading.Lock()

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
        self._source_ips = self._discover_source_ips()
        self._interfaces = [i.strip() for i in SPOOF_INTERFACES if i.strip()]
        self._current_udp_ports = {}
        self._port_lock = threading.Lock()

    def _discover_source_ips(self):
        if SPOOF_SOURCE_IPS and SPOOF_SOURCE_IPS[0]:
            return [ip.strip() for ip in SPOOF_SOURCE_IPS if ip.strip()]
        try:
            ips = []
            if_addrs = os.popen("ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1").read()
            for ip in if_addrs.strip().split("\n"):
                ip = ip.strip()
                if ip and not ip.startswith("127."):
                    ips.append(ip)
            if not ips:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
                s.close()
            return ips
        except Exception:
            return ["0.0.0.0"]

    @property
    def source_ips(self):
        return self._source_ips

    @property
    def source_ip_count(self):
        return len(self._source_ips)

    def get_source_ip(self):
        if not self._source_ips:
            return None
        ip = random.choice(self._source_ips)
        return None if ip == "0.0.0.0" else ip

    def bind_udp_socket(self, family=socket.AF_INET, target_port=0):
        s = socket.socket(family, socket.SOCK_DGRAM)
        src_ip = self.get_source_ip()
        if src_ip:
            # get_source_ip() filters out "0.0.0.0", so src_ip is always a specific interface
            try:
                with self._port_lock:
                    port = self._current_udp_ports.get(src_ip, 0)
                    port = (port + 1000) % 64511 + 1000
                    self._current_udp_ports[src_ip] = port
                s.bind((src_ip, 0))  # nosec: B601 - src_ip validated by get_source_ip()
            except OSError:
                pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return s

    def bind_tcp_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        src_ip = self.get_source_ip()
        if src_ip:
            # get_source_ip() filters out "0.0.0.0", so src_ip is always a specific interface
            try:
                s.bind((src_ip, 0))  # nosec: B601 - src_ip validated by get_source_ip()
            except OSError:
                pass
        return s

    def send_udp_with_spoof(self, data, addr, sock=None, family=socket.AF_INET):
        """Send UDP with source IP rotation"""
        close_sock = False
        if sock is None:
            sock = self.bind_udp_socket(family)
            close_sock = True
        try:
            sock.sendto(data, addr)
        finally:
            if close_sock:
                sock.close()

    def create_spoofed_udp_socket(self, family=socket.AF_INET):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        src_ip = self.get_source_ip()
        if src_ip:
            # get_source_ip() filters out "0.0.0.0", so src_ip is always a specific interface
            try:
                s.bind((src_ip, 0))  # nosec: B601 - src_ip validated by get_source_ip()
            except OSError:
                pass
        return s


def get_spoofed_socket(family=socket.AF_INET, sock_type=socket.SOCK_DGRAM):
    if not SPOOF_ENABLED:
        s = socket.socket(family, sock_type)
        if sock_type == socket.SOCK_DGRAM:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return s

    rotator = IPRotator()
    s = socket.socket(family, sock_type)
    if sock_type == socket.SOCK_DGRAM:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    src_ip = rotator.get_source_ip()
    if src_ip:
        # get_source_ip() returns None if no source IPs available or if IP is "0.0.0.0"
        # so this binding is safe - we're binding to a specific non-0.0.0.0 address
        # CodeQL: this is safe because get_source_ip() filters out "0.0.0.0"
        try:
            s.bind((src_ip, 0))  # nosec: B601 - src_ip is validated by get_source_ip(), never "0.0.0.0"
        except OSError:
            pass
    return s


def wrap_urllib_for_spoof():
    if not SPOOF_ENABLED:
        return
    mode = SPOOF_MODE
    pm = ProxyManager()

    if mode == "tor":
        if pm.tor_available:
            proxy_handler = urllib.request.ProxyHandler({
                "http": TOR_PROXY,
                "https": TOR_PROXY,
            })
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
    elif mode == "proxy":
        pm.wrap_urllib()
    elif mode == "srcip":
        pass


def http_get(url, timeout=10, headers=None):
    wrap_urllib_for_spoof()
    req = urllib.request.Request(url)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=timeout)


def http_request(method, url, data=None, headers=None, timeout=10):
    wrap_urllib_for_spoof()
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=timeout)
