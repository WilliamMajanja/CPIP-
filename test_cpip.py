#!/usr/bin/env python3
"""Basic test suite for CPIP. Run: python3 test_cpip.py"""
import json
import os
import subprocess
import sys
import time
import unittest
import urllib.request
import urllib.error

SERVER_CMD = [sys.executable, "server.py"]
BASE = "http://localhost:4180"


class TestCPIPServer(unittest.TestCase):
    """Starts a server, runs functional tests, stops it."""

    @classmethod
    def setUpClass(cls):
        env = os.environ.copy()
        env.update({
            "CPIP_PORT": "4180",
            "CPIP_MESH": "1",
            "CPIP_AVAHI": "0",
            "CPIP_NTP": "0",
            "CPIP_COVERT": "1",
            "CPIP_COVER_TRAFFIC": "0",
        })
        cls.proc = subprocess.Popen(SERVER_CMD, env=env,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        for _ in range(20):
            try:
                urllib.request.urlopen(f"{BASE}/")
                return
            except Exception:
                time.sleep(0.3)
        raise RuntimeError("Server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(5)

    def _get(self, path):
        with urllib.request.urlopen(f"{BASE}{path}") as r:
            return json.loads(r.read())

    def _post(self, path, data):
        req = urllib.request.Request(
            f"{BASE}{path}",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    # ── HTCPCP ────────────────────────────────────────────────────
    def test_root(self):
        d = self._get("/")
        self.assertIn("device", d)
        self.assertIn("version", d)

    def test_brew_tea(self):
        d = self._post("/tea", {})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._post("/", {"action": "when"})

    def test_brew_coffee(self):
        d = self._post("/coffee", {})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._post("/", {"action": "when"})

    def test_when(self):
        d = self._post("/", {"action": "when"})
        self.assertIn("status", d)

    def test_propfind(self):
        req = urllib.request.Request(f"{BASE}/", method="PROPFIND")
        with urllib.request.urlopen(req) as r:
            d = json.loads(r.read())
        self.assertIn("device", d)

    def test_418_teapot(self):
        try:
            urllib.request.urlopen(f"{BASE}/admin")
            self.fail("expected 418")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 418)

    # ── CPIP API ──────────────────────────────────────────────────
    def test_status(self):
        d = self._get("/cpip/status")
        self.assertIn("device", d)
        self.assertIn("version", d)

    def test_config(self):
        d = self._get("/cpip/config")
        self.assertIn("pot_id", d)
        self.assertIn("version", d)

    def test_brew_api(self):
        d = self._post("/cpip/brew", {"beverage": "tea"})
        self.assertIn("status", d)
        self._post("/", {"action": "when"})

    def test_history(self):
        d = self._get("/cpip/history")
        self.assertIn("count", d)
        self.assertIn("brews", d)

    def test_schedules(self):
        d = self._get("/cpip/schedules")
        self.assertIn("schedules", d)

    def test_pots(self):
        d = self._get("/cpip/pots")
        self.assertIn("pots", d)

    def test_metrics(self):
        with urllib.request.urlopen(f"{BASE}/cpip/metrics") as r:
            body = r.read().decode()
        self.assertIn("cpip_", body)

    # ── Mesh API ──────────────────────────────────────────────────
    def test_mesh_status(self):
        d = self._get("/cpip/mesh/status")
        self.assertIn("peers", d)
        self.assertIn("inbox", d)

    def test_mesh_peers(self):
        d = self._get("/cpip/mesh/peers")
        self.assertIn("peers", d)

    def test_mesh_inbox(self):
        d = self._get("/cpip/mesh/inbox")
        self.assertIn("messages", d)

    def test_mesh_routes(self):
        d = self._get("/cpip/mesh/routes")
        self.assertIn("routes", d)

    def test_mesh_sat(self):
        d = self._get("/cpip/mesh/sat")
        self.assertIn("enabled", d)

    def test_mesh_radio(self):
        d = self._get("/cpip/mesh/radio")
        self.assertIn("enabled", d)

    def test_mesh_mobile(self):
        d = self._get("/cpip/mesh/mobile")
        self.assertIn("enabled", d)

    # ── Covert Channel ────────────────────────────────────────────
    def test_covert_encode_decode(self):
        enc = self._post("/cpip/mesh/encode", {"message": "hello"})
        self.assertIn("accept_additions_header", enc)
        dec = self._post("/cpip/mesh/decode",
                         {"accept_additions": enc["accept_additions_header"]})
        self.assertEqual(dec.get("message"), "hello")

    # ── Defense ───────────────────────────────────────────────────
    def test_defense_get(self):
        d = self._get("/cpip/defense")
        self.assertIn("418_teapot", d)
        self.assertIn("blacklist", d)

    def test_defense_clear(self):
        d = self._post("/cpip/defense", {"action": "clear"})
        self.assertEqual(d.get("status"), "blacklist_cleared")

    # ── Dashboard ─────────────────────────────────────────────────
    def test_dashboard(self):
        with urllib.request.urlopen(f"{BASE}/dashboard") as r:
            body = r.read().decode()
        self.assertIn("CPIP", body)
        self.assertIn("dashboard", body.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
