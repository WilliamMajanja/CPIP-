#!/usr/bin/env python3
"""CPIP Terminal UI — OpenTUI-based interactive client for CPIP v5.1.0"""

import json
import os
import urllib.request
import urllib.error
import sys
from typing import Optional

from opentui import (
    render, Box, Text, Input, Select, ScrollBox, Markdown,
    TextTable, Spacer, Row, Column, Signal, component,
    computed, effect, BorderStyle,
)
from opentui.hooks import use_keyboard, use_terminal_dimensions

CPIP_HOST = os.environ.get("CPIP_HOST", "localhost")
CPIP_PORT = int(os.environ.get("CPIP_PORT", "4180"))
BASE_URL = f"http://{CPIP_HOST}:{CPIP_PORT}"
COVERT_KEY = os.environ.get("CPIP_COVERT_KEY", "")


def _cpip_hmac(method: str, path: str) -> str:
    if not COVERT_KEY:
        return ""
    import hmac as _hmac
    import hashlib
    ts = int(__import__('time').time())
    sig = _hmac.new(
        COVERT_KEY.encode(), f"{ts}:{method}:{path}".encode(), hashlib.sha256
    ).hexdigest()
    return f"{ts}:{sig}"


def api(method: str, path: str, data: dict = None) -> Optional[dict]:
    url = f"{BASE_URL}{path}"
    try:
        headers = {"Content-Type": "application/json"} if data else {}
        token = _cpip_hmac(method, path)
        if token:
            headers["X-CPIP-HMAC"] = token
        if data:
            req = urllib.request.Request(
                url, data=json.dumps(data).encode(),
                headers=headers,
                method=method,
            )
        else:
            req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        return {"error": str(e)}


# ── Navigation ─────────────────────────────────────────────────────────
PAGES = [
    ("status", "Status"),
    ("brew", "Brew"),
    ("mesh", "Mesh"),
    ("covert", "Covert"),
    ("itf", "ITF Defense"),
    ("crypto", "Crypto"),
    ("ecc", "ECC"),
    ("dns", "DNS"),
    ("config", "Config"),
    ("schedule", "Schedules"),
    ("history", "History"),
    ("about", "About"),
]

current_page = Signal("status")
status_data = Signal({})
brew_output = Signal("")
mesh_data = Signal({})
covert_output = Signal("")
itf_data = Signal({})
crypto_data = Signal({})
ecc_data = Signal({})
dns_data = Signal({})
config_data = Signal({})
schedule_data = Signal({})
history_data = Signal({})
loading = Signal(False)
error_msg = Signal("")


def fetch_page(page: str):
    loading.set(True)
    error_msg.set("")
    try:
        if page == "status":
            data = api("GET", "/cpip/status")
            if data: status_data.set(data)
        elif page == "mesh":
            data = api("GET", "/cpip/mesh/status")
            if data: mesh_data.set(data)
        elif page == "itf":
            data = api("GET", "/cpip/defense")
            if data: itf_data.set(data)
        elif page == "crypto":
            data = api("GET", "/cpip/crypto")
            if data: crypto_data.set(data)
        elif page == "config":
            data = api("GET", "/cpip/config")
            if data: config_data.set(data)
        elif page == "schedule":
            data = api("GET", "/cpip/schedules")
            if data: schedule_data.set(data)
        elif page == "history":
            data = api("GET", "/cpip/history")
            if data: history_data.set(data)
    except Exception as e:
        error_msg.set(str(e))
    loading.set(False)


# ── Components ─────────────────────────────────────────────────────────

@component
def Sidebar():
    items = []
    for key, label in PAGES:
        is_active = key == current_page()
        style = {"fg": "#fff", "bg": "#0366d6"} if is_active else {}
        items.append(
            Text(f"  {label}  ", **style, key=key)
        )

    return Box(
        Box(
            Text(" CPIP v5.1.0 ", bold=True, fg="#0366d6"),
            Text(" Coffee Protocol", fg="#888"),
            Spacer(height=1),
            *items,
            Spacer(),
            Text(" [q] Quit  [jk] Nav", fg="#555"),
            padding=1,
        ),
        width=20,
        border=True,
        border_style="round",
        border_color="#0366d6",
    )


@component
def StatusPanel():
    data = status_data()
    if not data:
        return Box(Text("No data — press [r] to refresh"), padding=1)

    rows = []
    for k, v in data.items():
        val = str(v)[:60]
        rows.append([k, val])

    return ScrollBox(
        Box(
            Text("System Status", bold=True, fg="#0366d6"),
            Spacer(height=1),
            TextTable(
                headers=["Field", "Value"],
                rows=rows,
                header_fg="#fff",
                header_bg="#0366d6",
            ),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def BrewPanel():
    beverage = Signal("coffee")
    additions = Signal("")
    result = Signal("")

    def brew():
        path = f"/{beverage()}"
        headers = {}
        if additions():
            headers["Accept-Additions"] = additions()
        url = f"{BASE_URL}{path}"
        try:
            req = urllib.request.Request(url, method="BREW",
                                         headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                result.set(resp.read().decode()[:200])
        except Exception as e:
            result.set(f"Error: {e}")

    def when():
        try:
            req = urllib.request.Request(f"{BASE_URL}/", method="WHEN")
            with urllib.request.urlopen(req, timeout=5) as resp:
                result.set(resp.read().decode()[:200])
        except Exception as e:
            result.set(f"Error: {e}")

    return Box(
        Text("Brew Control", bold=True, fg="#0366d6"),
        Spacer(height=1),
        Box(
            Select(
                options=[
                    ("coffee", "Coffee"),
                    ("tea", "Tea"),
                    ("espresso", "Espresso"),
                    ("latte", "Latte"),
                    ("cappuccino", "Cappuccino"),
                    ("americano", "Americano"),
                    ("cold_brew", "Cold Brew"),
                    ("mocha", "Mocha"),
                    ("matcha", "Matcha"),
                ],
                selected=beverage(),
                on_change=lambda i, o: beverage.set(o.value if o else "coffee"),
            ),
            Spacer(height=1),
            Input(
                placeholder="Additions (e.g. milk;variety=whole)",
                on_submit=lambda v: additions.set(v),
            ),
            Spacer(height=1),
            Row(
                Text(" [b] Brew ", bg="#28a745", fg="#fff", focusable=True),
                Text(" [w] When ", bg="#dc3545", fg="#fff", focusable=True),
                gap=1,
            ),
            padding=1,
            border=True,
            border_style="round",
        ),
        Spacer(height=1),
        Box(
            Text("Result:", bold=True),
            Text(result() or "Press [b] to brew, [w] to stop"),
            padding=1,
            border=True,
        ),
        padding=1,
    )


@component
def MeshPanel():
    data = mesh_data()
    peers = data.get("peers", []) if data else []
    inbox = data.get("inbox", []) if data else []

    peer_rows = [[p.get("pot_id", "?"), p.get("address", ""),
                  p.get("transport", "")] for p in peers[:20]]
    inbox_rows = [[m.get("from", "?"), str(m.get("msg", ""))[:40],
                   m.get("time", "")] for m in inbox[:20]]

    return ScrollBox(
        Box(
            Text("Mesh Network", bold=True, fg="#0366d6"),
            Spacer(height=1),
            Text(f"Peers: {len(peers)}  |  Inbox: {len(inbox)}", fg="#888"),
            Spacer(height=1),
            Text("Peers", bold=True),
            TextTable(
                headers=["POT ID", "Address", "Transport"],
                rows=peer_rows,
                header_fg="#fff", header_bg="#0366d6",
            ) if peer_rows else Text("No peers", fg="#888"),
            Spacer(height=1),
            Text("Inbox", bold=True),
            TextTable(
                headers=["From", "Message", "Time"],
                rows=inbox_rows,
                header_fg="#fff", header_bg="#0366d6",
            ) if inbox_rows else Text("No messages", fg="#888"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def CovertPanel():
    mode = Signal("encode")
    message = Signal("")
    output = Signal("")

    def encode():
        msg = message()
        if not msg:
            output.set("Enter a message first")
            return
        data = api("POST", "/cpip/mesh/encode", {"message": msg})
        if data:
            output.set(data.get("additions", str(data)))

    def decode():
        hdr = message()
        if not hdr:
            output.set("Enter a header first")
            return
        data = api("POST", "/cpip/mesh/decode", {"header": hdr})
        if data:
            output.set(data.get("message", str(data)))

    return ScrollBox(
        Box(
            Text("Covert Channel", bold=True, fg="#0366d6"),
            Spacer(height=1),
            Row(
                Box(
                    Text(" Encode ", bg="green" if mode() == "encode" else "#333", fg="#fff"),
                    Text(" Decode ", bg="blue" if mode() == "decode" else "#333", fg="#fff"),
                    gap=0,
                    on_click=lambda: mode.set("encode" if mode() == "decode" else "decode"),
                ),
                gap=1,
            ),
            Spacer(height=1),
            Input(
                placeholder="Message or header",
                on_submit=lambda v: message.set(v),
            ),
            Spacer(height=1),
            Row(
                Text(" [e] Execute ", bg="#28a745", fg="#fff", focusable=True),
                gap=1,
            ),
            Spacer(height=1),
            Box(
                Text("Output:"),
                Text(str(output())[:500] or "Enter data and press [e]"),
                padding=1,
                border=True,
            ),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def ITFPanel():
    data = itf_data()
    blacklist = data.get("blacklist", []) if data else []
    stealth = data.get("stealth", False) if data else False

    bl_rows = [[addr, "Blacklisted"] for addr in (blacklist or [])[:30]]

    return ScrollBox(
        Box(
            Text("ITF Defense", bold=True, fg="#0366d6"),
            Spacer(height=1),
            Text(f"Stealth Mode: {'ACTIVE' if stealth else 'disabled'}",
                 fg="green" if stealth else "#888", bold=stealth),
            Spacer(height=1),
            Text(f"Blacklisted IPs: {len(blacklist) if isinstance(blacklist, list) else 0}", bold=True),
            TextTable(
                headers=["IP", "Status"],
                rows=bl_rows,
                header_fg="#fff", header_bg="#dc3545",
            ) if bl_rows else Text("No blacklisted IPs", fg="#888"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def CryptoPanel():
    data = crypto_data()
    if not data:
        return Box(Text("No crypto data — press [r] to refresh"), padding=1)

    rows = [[k, str(v)[:50]] for k, v in data.items()]
    return ScrollBox(
        Box(
            Text("Cryptography", bold=True, fg="#0366d6"),
            Spacer(height=1),
            TextTable(
                headers=["Parameter", "Value"],
                rows=rows,
                header_fg="#fff", header_bg="#0366d6",
            ),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def ECCPanel():
    return ScrollBox(
        Box(
            Text("ECC / Identity", bold=True, fg="#0366d6"),
            Spacer(height=1),
            Text("Press [r] to refresh identity data"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def DNSPanel():
    return ScrollBox(
        Box(
            Text("Distributed DNS", bold=True, fg="#0366d6"),
            Spacer(height=1),
            Text("Press [r] to refresh DNS records"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def ConfigPanel():
    data = config_data()
    if not data:
        return Box(Text("No config data — press [r] to refresh"), padding=1)

    rows = [[k, str(v)[:60]] for k, v in data.items()]
    return ScrollBox(
        Box(
            Text("Configuration", bold=True, fg="#0366d6"),
            Spacer(height=1),
            TextTable(
                headers=["Key", "Value"],
                rows=rows,
                header_fg="#fff", header_bg="#0366d6",
            ),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def SchedulePanel():
    data = schedule_data()
    schedules = data if isinstance(data, list) else data.get("schedules", []) if data else []
    sched_rows = [[s.get("id", "?"), s.get("time", ""),
                   s.get("beverage", "")] for s in schedules[:20]]

    return ScrollBox(
        Box(
            Text("Brew Schedules", bold=True, fg="#0366d6"),
            Spacer(height=1),
            TextTable(
                headers=["ID", "Time", "Beverage"],
                rows=sched_rows,
                header_fg="#fff", header_bg="#0366d6",
            ) if sched_rows else Text("No schedules", fg="#888"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def HistoryPanel():
    data = history_data()
    history = data if isinstance(data, list) else data.get("history", []) if data else []
    hist_rows = [[h.get("time", ""), h.get("beverage", ""),
                  h.get("additions", ""), str(h.get("duration", ""))]
                 for h in history[:30]]

    return ScrollBox(
        Box(
            Text("Brew History", bold=True, fg="#0366d6"),
            Spacer(height=1),
            TextTable(
                headers=["Time", "Beverage", "Additions", "Duration"],
                rows=hist_rows,
                header_fg="#fff", header_bg="#0366d6",
            ) if hist_rows else Text("No brew history", fg="#888"),
            padding=1,
        ),
        scroll_y=True,
    )


@component
def AboutPanel():
    return ScrollBox(
        Box(
            Text("CPIP v5.1.0 — Coffee Pot Internet Protocol", bold=True),
            Spacer(height=1),
            Markdown(
                "## Protocol Support\n"
                "- RFC 2324 (HTCPCP)\n"
                "- RFC 7168 (HTCPCP-TEA)\n\n"
                "## Transports\n"
                "- LAN Mesh (UDP)\n"
                "- Satellite (Internet-wide)\n"
                "- Radio (LoRa / TNC)\n"
                "- Mobile (4G/5G)\n\n"
                "## Cryptography\n"
                "- AES-256-GCM (FIPS 197)\n"
                "- ECDSA/ECDH P-256 (FIPS 186-4)\n"
                "- HybridKEM: ECDH + Kyber\n\n"
                "## CLI Tools\n"
                "- `cpip tui` — Terminal UI (OpenTUI)\n"
                "- `b4dm4n-cw tui` — Crypto Workbench REPL\n\n"
                "## Controls\n"
                "- `[Tab]` / arrows: Navigate\n"
                "- `[r]`: Refresh current page\n"
                "- `[q]`: Quit\n"
                "- `[b]`: Brew (on Brew page)\n"
                "- `[w]`: When (on Brew page)\n"
                "- `[e]`: Execute (on Covert page)"
            ),
            padding=1,
        ),
        scroll_y=True,
    )


# ── Main Application ───────────────────────────────────────────────────

PANELS = {
    "status": StatusPanel,
    "brew": BrewPanel,
    "mesh": MeshPanel,
    "covert": CovertPanel,
    "itf": ITFPanel,
    "crypto": CryptoPanel,
    "ecc": ECCPanel,
    "dns": DNSPanel,
    "config": ConfigPanel,
    "schedule": SchedulePanel,
    "history": HistoryPanel,
    "about": AboutPanel,
}


@component
def App():
    dims = use_terminal_dimensions()

    # Keyboard handler
    def handle_key(key):
        if key == "q":
            sys.exit(0)
        elif key == "r":
            page = current_page()
            fetch_page(page)
        elif key in ("up", "k"):
            pages = [p[0] for p in PAGES]
            idx = pages.index(current_page())
            current_page.set(pages[(idx - 1) % len(pages)])
        elif key in ("down", "j"):
            pages = [p[0] for p in PAGES]
            idx = pages.index(current_page())
            current_page.set(pages[(idx + 1) % len(pages)])
        elif key in ("tab", "right", "l"):
            pages = [p[0] for p in PAGES]
            idx = pages.index(current_page())
            current_page.set(pages[(idx + 1) % len(pages)])
        elif key in ("left", "h"):
            pages = [p[0] for p in PAGES]
            idx = pages.index(current_page())
            current_page.set(pages[(idx - 1) % len(pages)])
        elif key == "b" and current_page() == "brew":
            pass  # handled by BrewPanel
        elif key == "w" and current_page() == "brew":
            pass
        elif key == "e" and current_page() == "covert":
            pass
        return True

    use_keyboard(handle_key)

    # Fetch initial data
    effect(lambda: fetch_page(current_page()), [current_page])

    cur_page = current_page()
    Panel = PANELS.get(cur_page, StatusPanel)

    return Box(
        Row(
            Sidebar(),
            Box(
                Panel(),
                flex_grow=1,
                padding=1,
            ),
            flex_grow=1,
            gap=0,
        ),
        width=dims.width if dims else None,
        height=dims.height if dims else None,
    )


def main():
    render(App)


if __name__ == "__main__":
    main()
