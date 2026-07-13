"""radio_protocol.py — CPIP Radio Interface (Python side)
Communicates with the C radio_if binary over a Unix domain socket.

Usage:
    from radio_protocol import RadioInterface
    ri = RadioInterface()
    ri.start(mode="lora")           # Real LoRa hardware (default)
    ri.start(mode="tnc")            # KISS TNC over serial
    ri.start(mode="sim")            # Simulation (testing only)
    ri.send(b"hello")
    for pkt in ri.receive():
        print(pkt)
    ri.stop()
"""

import json
import os
import select
import socket
import struct
import subprocess
import threading
import time

RADIO_SOCK_PATH = "/tmp/cpip-radio.sock"
RADIO_BIN = os.path.join(os.path.dirname(__file__), "radio_if")

# Protocol constants (mirrors radio_if.h)
RADIO_PKT_HELLO = 0x01
RADIO_PKT_CONFIG = 0x02
RADIO_PKT_TX_DATA = 0x03
RADIO_PKT_RX_DATA = 0x04
RADIO_PKT_STATUS = 0x05
RADIO_PKT_ERROR = 0x06
RADIO_PKT_BYE = 0x07
RADIO_PKT_PING = 0x08
RADIO_PKT_PONG = 0x09

RADIO_MAX_PAYLOAD = 512


class RadioError(Exception):
    pass


class RadioInterface:
    """Manages the C radio_if subprocess over a Unix socket."""

    def __init__(self):
        self._proc = None
        self._sock = None
        self._rx_thread = None
        self._running = False
        self._rx_queue = []
        self._rx_lock = threading.Lock()
        self._status = {}

    def start(self, mode="lora", frequency=915000000, sf=9, bandwidth=125000,
              tx_power=17, device="/dev/spidev0.0", baud=115200, binary=None):
        """Launch the C radio_if binary and connect over Unix socket."""
        if self._running:
            return

        binary = binary or RADIO_BIN
        if not os.path.exists(binary):
            raise RadioError(f"Radio binary not found: {binary}")

        # Start C process
        args = [binary, f"--{mode}"]
        if mode == "lora":
            args += [f"--freq", str(frequency), "--sf", str(sf),
                     "--bw", str(bandwidth), "--power", str(tx_power)]
        elif mode == "tnc":
            args += ["--device", device, "--baud", str(baud)]

        try:
            os.unlink(RADIO_SOCK_PATH)
        except FileNotFoundError:
            pass

        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for socket
        for _ in range(50):
            if os.path.exists(RADIO_SOCK_PATH):
                break
            time.sleep(0.1)
        else:
            self.stop()
            raise RadioError("Radio interface did not start")

        # Connect
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect(RADIO_SOCK_PATH)
        self._sock.settimeout(None)  # block indefinitely

        # Wait for HELLO
        typ, payload = self._read_frame()
        if typ != RADIO_PKT_HELLO:
            self.stop()
            raise RadioError(f"Expected HELLO, got {typ}")

        self._running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

        # Send config
        cfg = json.dumps({
            "mode": mode, "frequency": frequency,
            "sf": sf, "bandwidth": bandwidth, "tx_power": tx_power,
            "device": device, "baud": baud,
        })
        self._send(RADIO_PKT_CONFIG, cfg.encode())
        typ, _ = self._read_frame()
        if typ != RADIO_PKT_CONFIG:
            typ, err = self._read_frame()
            raise RadioError(f"Config rejected: {err}")

    def stop(self):
        """Shut down the radio interface."""
        self._running = False
        try:
            if self._sock:
                self._send(RADIO_PKT_BYE)
                self._sock.close()
        except Exception:
            pass
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.kill()
        for path in (RADIO_SOCK_PATH,):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self._sock = None
        self._proc = None

    def send(self, data: bytes):
        """Transmit a packet over the radio."""
        if not self._running:
            raise RadioError("Radio not running")
        self._send(RADIO_PKT_TX_DATA, data)
        typ, _ = self._read_frame()
        if typ != RADIO_PKT_TX_DATA:
            typ, err = self._read_frame()
            raise RadioError(f"TX failed: {err}")

    def receive(self, timeout=0.1) -> list:
        """Return all received packets since last call."""
        with self._rx_lock:
            packets = list(self._rx_queue)
            self._rx_queue.clear()
        return packets

    def status(self) -> dict:
        """Query radio status from the C process."""
        if not self._running:
            return {"running": False}
        with self._rx_lock:
            s = dict(self._status) if self._status else {}
        return s

    def _send(self, typ: int, payload: bytes = b""):
        """Write a frame to the socket."""
        if not self._sock:
            return
        length = len(payload)
        header = struct.pack("!HB", length, typ)
        self._sock.sendall(header + payload)

    def _read_frame(self) -> tuple:
        """Read a single frame from the socket."""
        header = self._sock.recv(3)
        if len(header) < 3:
            raise RadioError("Connection closed")
        length, typ = struct.unpack("!HB", header)
        payload = b""
        if length > 0:
            while len(payload) < length:
                chunk = self._sock.recv(length - len(payload))
                if not chunk:
                    raise RadioError("Connection closed")
                payload += chunk
        return typ, payload

    def _rx_loop(self):
        """Background thread: receive frames from C process."""
        while self._running and self._sock:
            try:
                typ, payload = self._read_frame()
            except Exception:
                break

            if typ == RADIO_PKT_RX_DATA:
                with self._rx_lock:
                    self._rx_queue.append(payload)

            elif typ == RADIO_PKT_STATUS:
                try:
                    with self._rx_lock:
                        self._status = json.loads(payload.decode())
                except Exception:
                    pass

            elif typ == RADIO_PKT_ERROR:
                err_code = payload[0] if payload else 255
                err_msg = payload[1:].decode(errors="replace") if len(payload) > 1 else ""
                print(f"[RADIO] Error {err_code}: {err_msg}", flush=True)

            elif typ == RADIO_PKT_BYE:
                break

            elif typ in (RADIO_PKT_HELLO, RADIO_PKT_PONG, RADIO_PKT_CONFIG):
                pass

            else:
                print(f"[RADIO] Unknown frame type {typ}", flush=True)
