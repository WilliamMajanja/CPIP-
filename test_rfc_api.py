"""Contract tests for the RFC extension API and its provider adapters."""

import tempfile
import unittest
from pathlib import Path

from providers import rfc_api
from providers.evidence import EvidenceProvider
from providers.circumvention import CircumventionProvider


class TestRFCRoutes(unittest.TestCase):
    def test_provider_status_routes_return_json_success(self):
        paths = (
            "/cpip/cell/status", "/cpip/sdr/status", "/cpip/crypto/pqc-status",
            "/cpip/radio/status", "/cpip/ss7/status", "/cpip/scorer/status",
            "/cpip/intel/status", "/cpip/hardware/status", "/cpip/sensors/status",
            "/cpip/field/status", "/cpip/tamper/status", "/cpip/deception/status",
            "/cpip/ai/status", "/cpip/modem/status", "/cpip/ob-channel/status",
            "/cpip/power/status", "/cpip/emsec/status", "/cpip/carrier/status",
            "/cpip/pq-mesh/status", "/cpip/duress/status",
            "/cpip/mesh-security/status", "/cpip/evidence/status",
            "/cpip/circumvention/status", "/cpip/airgap/status", "/cpip/hygiene/status",
        )
        for path in paths:
            with self.subTest(path=path):
                result = rfc_api.route_get(path, {})
                self.assertIsNotNone(result)
                self.assertEqual(result[0], 200)
                self.assertIsInstance(result[1], dict)

    def test_intelligence_risk_score_validates_and_reads_query(self):
        self.assertEqual(rfc_api.route_get("/cpip/intel/risk-score", {})[0], 400)
        status, result = rfc_api.route_get(
            "/cpip/intel/risk-score", {"mcc": ["310"], "mnc": ["260"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["mcc"], "310")
        self.assertEqual(result["mnc"], "260")

    def test_provider_route_contracts(self):
        status, result = rfc_api.route_post("/cpip/tamper/test", {}, {})
        self.assertEqual(status, 200)
        self.assertEqual(result["type"], "test")

        status, result = rfc_api.route_post(
            "/cpip/airgap/qr-send", {"data": "coffee"}, {}
        )
        self.assertEqual(status, 200)
        self.assertIn(result["status"], ("encoded", "ready_to_display"))
        self.assertTrue(result["qr_data"])

        status, result = rfc_api.route_post(
            "/cpip/carrier/register-webhook", {}, {}
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["registered"])

    def test_disabled_side_channel_is_not_reported_as_sent(self):
        status, result = rfc_api.route_post(
            "/cpip/ob-channel/send",
            {"channel": "nfc", "peer": "peer-1", "message": "test"},
            {},
        )
        self.assertIn(status, (501, 503))
        self.assertFalse(result.get("sent", False))
        self.assertIn("error", result)

    def test_evidence_is_persisted_and_chain_verified(self):
        original_dir = EvidenceProvider._evidence_dir
        original_chain = EvidenceProvider._chain
        try:
            with tempfile.TemporaryDirectory() as directory:
                EvidenceProvider._evidence_dir = Path(directory)
                EvidenceProvider._chain = []
                EvidenceProvider.start()
                entry = EvidenceProvider.capture({"event": "test"})
                self.assertTrue(EvidenceProvider.verify(entry["id"])["valid"])
                self.assertTrue((Path(directory) / f"{entry['id']}.json").is_file())
                EvidenceProvider._chain = []
                EvidenceProvider.start()
                self.assertTrue(EvidenceProvider.verify(entry["id"])["valid"])
        finally:
            EvidenceProvider._evidence_dir = original_dir
            EvidenceProvider._chain = original_chain

    def test_circumvention_http_wrapper_returns_bytes(self):
        previous = CircumventionProvider._active_mode
        try:
            CircumventionProvider._active_mode = "https"
            wrapped = CircumventionProvider.wrap_message(b"sample")
            self.assertIsInstance(wrapped, bytes)
            self.assertTrue(wrapped.startswith(b"POST /upload HTTP/1.1"))
        finally:
            CircumventionProvider._active_mode = previous

    def test_mesh_e2ee_roundtrip_has_ephemeral_public_key(self):
        from server import ECP256, MeshNode, POT_ID

        original = (MeshNode.node_seed, MeshNode.node_pubkey, MeshNode.node_address)
        try:
            pub, seed, *_ = ECP256.generate_keypair()
            MeshNode.node_seed = seed
            MeshNode.node_pubkey = pub
            MeshNode.node_address = ECP256.pubkey_to_address(pub)
            encrypted = MeshNode._e2ee_encrypt("private mesh message", POT_ID)
            self.assertTrue(encrypted["e2ee"])
            self.assertTrue(encrypted["eph_pub"])
            decrypted = MeshNode._e2ee_decrypt(
                encrypted["data"], encrypted["from_addr"], encrypted["eph_pub"]
            )
            self.assertEqual(decrypted, "private mesh message")
        finally:
            MeshNode.node_seed, MeshNode.node_pubkey, MeshNode.node_address = original


if __name__ == "__main__":
    unittest.main()
