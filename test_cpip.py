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
TEST_PORT = int(os.environ.get("CPIP_TEST_PORT", "4182"))
BASE = f"http://localhost:{TEST_PORT}"


class TestCPIPServer(unittest.TestCase):
    """Starts a server, runs functional tests, stops it."""

    @classmethod
    def setUpClass(cls):
        env = os.environ.copy()
        env.update({
            "CPIP_PORT": str(TEST_PORT),
            "CPIP_MESH": "1",
            "CPIP_SAT": "1",
            "CPIP_MOBILE": "1",
            "CPIP_AVAHI": "0",
            "CPIP_NTP": "0",
            "CPIP_COVERT": "1",
            "CPIP_COVER_TRAFFIC": "0",
            "CPIP_THERMOS": "1",
        })
        cls.proc = subprocess.Popen(SERVER_CMD, env=env,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        for _ in range(20):
            try:
                d = json.loads(urllib.request.urlopen(f"{BASE}/").read())
                cls.POT_ID = d.get("pot_id", "test-pot")
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

    def _when(self):
        try:
            req = urllib.request.Request(f"{BASE}/", method="WHEN")
            urllib.request.urlopen(req)
        except Exception:
            pass

    # ── HTCPCP ────────────────────────────────────────────────────
    def test_root(self):
        d = self._get("/")
        self.assertIn("device", d)
        self.assertIn("protocol", d)

    def test_brew_tea(self):
        self._when()
        d = self._post("/tea", {})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._when()

    def test_brew_coffee(self):
        self._when()
        d = self._post("/coffee", {})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._when()

    def test_when(self):
        self._when()
        req = urllib.request.Request(f"{BASE}/", method="WHEN")
        with urllib.request.urlopen(req) as r:
            d = json.loads(r.read())
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

    def test_additions(self):
        self._when()
        d = self._post("/tea", {"additions": [{"name": "milk", "variety": "whole"}]})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._when()

    def test_alcohol_418(self):
        self._when()
        d = self._post("/coffee", {"additions": [{"name": "whisky"}]})
        if d.get("status") == 418:
            self.assertEqual(d.get("error"), "I'm a teapot")
        else:
            self._when()

    # ── CPIP API ──────────────────────────────────────────────────
    def test_status(self):
        self._when()
        d = self._get("/cpip/status")
        self.assertIn("cpip_version", d)
        self.assertIn("pot_id", d)

    def test_config(self):
        d = self._get("/cpip/config")
        self.assertIn("pot_id", d)
        self.assertIn("version", d)
        self.assertIn("node_address", d)

    def test_brew_api(self):
        self._when()
        d = self._post("/cpip/brew", {"beverage": "tea"})
        self.assertIn("status", d)
        self._when()

    def test_brew_with_additions(self):
        self._when()
        d = self._post("/cpip/brew", {
            "beverage": "tea",
            "additions": [{"name": "milk", "variety": "whole"}],
        })
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        self._when()

    def test_brew_with_duration(self):
        self._when()
        d = self._post("/cpip/brew", {"beverage": "coffee", "duration": 5})
        self.assertIn(d.get("status"), ("brewing", "stopped"))
        time.sleep(0.5)
        self._when()

    def test_brew_api_already_brewing(self):
        self._when()
        self._post("/cpip/brew", {"beverage": "coffee"})
        try:
            self._post("/cpip/brew", {"beverage": "coffee"})
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 409)
            d = json.loads(e.read())
            self.assertEqual(d.get("error"), "Already brewing")
        self._when()

    def test_history(self):
        d = self._get("/cpip/history")
        self.assertIn("count", d)
        self.assertIn("history", d)

    def test_schedules(self):
        d = self._get("/cpip/schedules")
        self.assertIn("schedules", d)

    def test_schedule_create(self):
        self._when()
        d = self._post("/cpip/schedule", {"time": "2099-01-01T12:00:00", "beverage": "tea"})
        self.assertIn("status", d)
        self.assertIn("schedule", d)

    def test_pots(self):
        d = self._get("/cpip/pots")
        self.assertIn("pots", d)

    def test_metrics(self):
        with urllib.request.urlopen(f"{BASE}/cpip/metrics") as r:
            body = r.read().decode()
        self.assertIn("cpip_", body)

    def test_discover(self):
        d = self._get("/cpip/discover")
        self.assertIn("pots", d)

    def test_cpip_config_put(self):
        req = urllib.request.Request(
            f"{BASE}/cpip/config",
            data=json.dumps({"device": "hyper-text"}).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req) as r:
            d = json.loads(r.read())
        self.assertIn("status", d)

    def test_webhooks(self):
        d = self._get("/cpip/webhooks")
        self.assertIn("webhooks", d)
        d2 = self._post("/cpip/webhooks", {"url": "http://example.com/hook"})
        self.assertEqual(d2.get("status"), "webhook added")

    # ── Mesh API ──────────────────────────────────────────────────
    def test_mesh_status(self):
        d = self._get("/cpip/mesh/status")
        # Response wraps mesh info under "mesh" key
        mesh = d.get("mesh", d)
        self.assertIn("peers", mesh)
        self.assertIn("inbox_count", mesh)

    def test_mesh_peers(self):
        d = self._get("/cpip/mesh/peers")
        self.assertIn("peers", d)

    def test_mesh_inbox(self):
        d = self._get("/cpip/mesh/inbox")
        self.assertIn("messages", d)

    def test_mesh_routes(self):
        d = self._get("/cpip/mesh/routes")
        self.assertIn("routes", d)

    def test_mesh_send_self(self):
        d = self._post("/cpip/mesh/send", {"dst": self.POT_ID, "data": "ping"})
        self.assertIn("status", d)

    def test_mesh_broadcast(self):
        d = self._post("/cpip/mesh/broadcast", {"data": "hello mesh"})
        self.assertIn("peers_reached", d)

    def test_mesh_sat(self):
        d = self._get("/cpip/mesh/sat")
        self.assertIn("enabled", d)

    def test_mesh_radio(self):
        d = self._get("/cpip/mesh/radio")
        self.assertIn("enabled", d)

    def test_mesh_mobile(self):
        d = self._get("/cpip/mesh/mobile")
        self.assertIn("enabled", d)

    def test_mesh_queued(self):
        d = self._get("/cpip/mesh/queued")
        self.assertIn("queued", d)

    def test_mesh_deaddrop_list(self):
        d = self._get("/cpip/mesh/deaddrop?action=list")
        self.assertIn("dead_drops", d)

    # ── ECC ───────────────────────────────────────────────────────
    def test_ecc_address(self):
        d = self._get("/cpip/mesh/ecc/address")
        self.assertIn("address", d)

    def test_ecc_book(self):
        d = self._get("/cpip/mesh/ecc/book")
        self.assertIn("entries", d)

    # ── Covert Channel ────────────────────────────────────────────
    def test_covert_encode_decode(self):
        enc = self._post("/cpip/mesh/encode", {"message": "hello"})
        self.assertIn("accept_additions_header", enc)
        dec = self._post("/cpip/mesh/decode",
                         {"accept_additions": enc["accept_additions_header"]})
        self.assertEqual(dec.get("message"), "hello")

    def test_covert_encode_long_message(self):
        msg = "The coffee is ready at midnight. Meet me in the usual place."
        enc = self._post("/cpip/mesh/encode", {"message": msg})
        self.assertIn("accept_additions_header", enc)
        dec = self._post("/cpip/mesh/decode",
                         {"accept_additions": enc["accept_additions_header"]})
        self.assertEqual(dec.get("message"), msg)

    def test_covert_encode_empty(self):
        try:
            self._post("/cpip/mesh/encode", {"message": ""})
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_covert_status(self):
        d = self._get("/cpip/mesh/covert_status")
        self.assertIn("enabled", d)

    # ── Defense ───────────────────────────────────────────────────
    def test_defense_get(self):
        d = self._get("/cpip/defense")
        self.assertIn("418_teapot", d)
        self.assertIn("blacklist", d)

    def test_defense_clear(self):
        d = self._post("/cpip/defense", {"action": "clear"})
        self.assertEqual(d.get("status"), "blacklist_cleared")

    def test_defense_whitelist(self):
        d = self._post("/cpip/defense", {"action": "whitelist", "addr": "10.0.0.1"})
        self.assertIn("status", d)

    def test_defense_probe(self):
        d = self._post("/cpip/defense", {"action": "probe", "addr": "10.0.0.1"})
        self.assertIn("status", d)

    # ── Dashboard ─────────────────────────────────────────────────
    def test_dashboard(self):
        with urllib.request.urlopen(f"{BASE}/dashboard") as r:
            body = r.read().decode()
        self.assertIn("CPIP", body)
        # The dashboard page title has "Coffee Protocol" in it
        self.assertIn("Coffee", body)

    def test_dashboard_brew_tab(self):
        with urllib.request.urlopen(f"{BASE}/dashboard") as r:
            body = r.read().decode()
        self.assertIn("Brew", body) or self.assertIn("brew", body)
        self.assertIn("Mesh", body) or self.assertIn("mesh", body)

    def test_dashboard_schedule_tab(self):
        with urllib.request.urlopen(f"{BASE}/dashboard") as r:
            body = r.read().decode()
        self.assertIn("Schedule", body) or self.assertIn("schedule", body)

    # ── Web Directory ─────────────────────────────────────────────
    def test_web_dir_index(self):
        """Serve web/index.html if it exists."""
        web_index = os.path.join(os.path.dirname(__file__), "web", "index.html")
        if os.path.isfile(web_index):
            with urllib.request.urlopen(f"{BASE}/dashboard") as r:
                body = r.read().decode()
            self.assertIn("CPIP", body)

    # ── Covert Brew ───────────────────────────────────────────────
    def test_covert_brew(self):
        d = self._post("/cpip/mesh/brew_covert", {
            "message": "secret",
            "dst": self.POT_ID,
        })
        self.assertIn("status", d)

    # ── NTP ───────────────────────────────────────────────────────
    def test_ntp_status_key(self):
        d = self._get("/cpip/status")
        self.assertIn("ntp", d)

    # ── Crypto API ────────────────────────────────────────────────
    # (tested comprehensively in test_crypto.py)

    # ── Security Headers ─────────────────────────────────────────
    def test_security_headers(self):
        import urllib.request
        req = urllib.request.Request(f"{BASE}/")
        with urllib.request.urlopen(req) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
        self.assertIn("x-content-type-options", headers, 
                      f"Missing security headers. Got: {list(headers.keys())[:10]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)