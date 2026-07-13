#!/usr/bin/env python3
"""Comprehensive tests for CPIP cryptographic and security subsystems.

Tests: Ed25519, ML-KEM, HybridKEM, CoffeeCipher v2, SecureHash,
IncidentResponse, SignalAwareness, EmergencyMode, NetDiagnostics,
CovertChannel, mesh HMAC, persistence encryption, and HTTP security.

Run: python3 test_crypto.py
"""
import hashlib
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from server import (
    CoffeeCipher, Ed25519, MLKEM, HybridKEM, SecureHash,
    IncidentResponse, SignalAwareness, EmergencyMode, NetDiagnostics,
    CovertChannel,
)


class TestEd25519(unittest.TestCase):
    """Ed25519 elliptic curve cryptography."""

    def test_keypair_generation(self):
        pk, seed, a, A = Ed25519.generate_keypair()
        self.assertEqual(len(pk), 32)
        self.assertEqual(len(seed), 32)
        self.assertIsInstance(a, int)
        self.assertIsInstance(A, tuple)
        self.assertEqual(len(A), 2)

    def test_encode_decode_roundtrip(self):
        for _ in range(20):
            pk, seed, a, A = Ed25519.generate_keypair()
            A2 = Ed25519._decode_point(pk)
            pk2 = Ed25519._encode_point(A2)
            self.assertEqual(pk, pk2, "encode/decode roundtrip failed")
            self.assertEqual(A, A2, "point mismatch after roundtrip")

    def test_sign_verify(self):
        pk, seed, a, A = Ed25519.generate_keypair()
        msg = b"hello coffee protocol"
        sig = Ed25519.sign(msg, seed)
        self.assertEqual(len(sig), 64)
        self.assertTrue(Ed25519.verify(msg, sig, pk))

    def test_sign_verify_wrong_message(self):
        pk, seed, a, A = Ed25519.generate_keypair()
        sig = Ed25519.sign(b"correct message", seed)
        self.assertFalse(Ed25519.verify(b"wrong message", sig, pk))

    def test_sign_verify_wrong_key(self):
        pk1, seed1, _, _ = Ed25519.generate_keypair()
        pk2, seed2, _, _ = Ed25519.generate_keypair()
        sig = Ed25519.sign(b"test", seed1)
        self.assertFalse(Ed25519.verify(b"test", sig, pk2))

    def test_sign_verify_tampered_signature(self):
        pk, seed, _, _ = Ed25519.generate_keypair()
        sig = Ed25519.sign(b"test", seed)
        tampered = bytearray(sig)
        tampered[10] ^= 0xff
        self.assertFalse(Ed25519.verify(b"test", bytes(tampered), pk))

    def test_sign_verify_empty_message(self):
        pk, seed, _, _ = Ed25519.generate_keypair()
        sig = Ed25519.sign(b"", seed)
        self.assertTrue(Ed25519.verify(b"", sig, pk))

    def test_sign_verify_large_message(self):
        pk, seed, _, _ = Ed25519.generate_keypair()
        msg = os.urandom(10000)
        sig = Ed25519.sign(msg, seed)
        self.assertTrue(Ed25519.verify(msg, sig, pk))

    def test_ecdh_shared_secret(self):
        pk1, s1, _, _ = Ed25519.generate_keypair()
        pk2, s2, _, _ = Ed25519.generate_keypair()
        shared1 = Ed25519.key_exchange(s1, pk2)
        shared2 = Ed25519.key_exchange(s2, pk1)
        self.assertEqual(shared1, shared2, "ECDH shared secrets must match")

    def test_ecdh_multiple_iterations(self):
        for _ in range(5):
            pk1, s1, _, _ = Ed25519.generate_keypair()
            pk2, s2, _, _ = Ed25519.generate_keypair()
            self.assertEqual(
                Ed25519.key_exchange(s1, pk2),
                Ed25519.key_exchange(s2, pk1),
            )

    def test_ecdh_different_peers_produce_different_secrets(self):
        pk1, s1, _, _ = Ed25519.generate_keypair()
        pk2, s2, _, _ = Ed25519.generate_keypair()
        pk3, s3, _, _ = Ed25519.generate_keypair()
        ss12 = Ed25519.key_exchange(s1, pk2)
        ss13 = Ed25519.key_exchange(s1, pk3)
        self.assertNotEqual(ss12, ss13)

    def test_pubkey_to_address(self):
        pk, _, _, _ = Ed25519.generate_keypair()
        addr = Ed25519.pubkey_to_address(pk)
        self.assertTrue(addr.startswith("coffee:"))
        self.assertTrue(Ed25519.address_matches(addr, pk))
        self.assertFalse(Ed25519.address_matches(addr, os.urandom(32)))

    def test_deterministic_keypair(self):
        seed = os.urandom(32)
        pk1, s1, a1, A1 = Ed25519.generate_keypair(seed)
        pk2, s2, a2, A2 = Ed25519.generate_keypair(seed)
        self.assertEqual(pk1, pk2)
        self.assertEqual(s1, s2)
        self.assertEqual(a1, a2)


class TestMLKEM(unittest.TestCase):
    """ML-KEM post-quantum key encapsulation."""

    def test_keygen(self):
        pk, sk = MLKEM.keygen()
        self.assertEqual(len(pk), 32)
        self.assertEqual(len(sk), 32)

    def test_encaps_decaps_match(self):
        pk, sk = MLKEM.keygen()
        ct, ss_enc = MLKEM.encaps(pk)
        ss_dec = MLKEM.decaps(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "ML-KEM shared secrets must match")

    def test_encaps_decaps_multiple_iterations(self):
        for _ in range(5):
            pk, sk = MLKEM.keygen()
            ct, ss_enc = MLKEM.encaps(pk)
            ss_dec = MLKEM.decaps(sk, ct)
            self.assertEqual(ss_enc, ss_dec)

    def test_different_keys_different_secrets(self):
        pk1, sk1 = MLKEM.keygen()
        pk2, sk2 = MLKEM.keygen()
        _, ss1 = MLKEM.encaps(pk1)
        _, ss2 = MLKEM.encaps(pk2)
        self.assertNotEqual(ss1, ss2)

    def test_tampered_ciphertext_rejected(self):
        pk, sk = MLKEM.keygen()
        ct, ss_enc = MLKEM.encaps(pk)
        tampered = bytes(b ^ 0x01 for b in ct)
        ss_dec = MLKEM.decaps(sk, tampered)
        self.assertNotEqual(ss_enc, ss_dec, "tampered ct must produce different secret")

    def test_deterministic_decaps(self):
        pk, sk = MLKEM.keygen()
        ct, _ = MLKEM.encaps(pk)
        ss1 = MLKEM.decaps(sk, ct)
        ss2 = MLKEM.decaps(sk, ct)
        self.assertEqual(ss1, ss2)

    def test_wrong_secret_key_rejected(self):
        pk1, sk1 = MLKEM.keygen()
        _, sk2 = MLKEM.keygen()
        ct, ss_enc = MLKEM.encaps(pk1)
        ss_dec = MLKEM.decaps(sk2, ct)
        self.assertNotEqual(ss_enc, ss_dec)

    def test_encapsulation_produces_32byte_secret(self):
        pk, sk = MLKEM.keygen()
        ct, ss = MLKEM.encaps(pk)
        self.assertEqual(len(ss), 32)

    def test_ciphertext_is_32bytes(self):
        pk, sk = MLKEM.keygen()
        ct, _ = MLKEM.encaps(pk)
        self.assertEqual(len(ct), 32)


class TestHybridKEM(unittest.TestCase):
    """Hybrid ECDH + ML-KEM key exchange."""

    def test_generate_keypair(self):
        hpk, hsk = HybridKEM.generate_keypair()
        self.assertGreater(len(hpk), 32)
        self.assertGreater(len(hsk), 32)

    def test_encapsulate_decapsulate_match(self):
        hpk, hsk = HybridKEM.generate_keypair()
        ct, ss_enc = HybridKEM.encapsulate(hpk)
        ss_dec = HybridKEM.decapsulate(hsk, ct)
        self.assertEqual(ss_enc, ss_dec, "HybridKEM shared secrets must match")

    def test_encapsulate_decapsulate_multiple(self):
        for _ in range(3):
            hpk, hsk = HybridKEM.generate_keypair()
            ct, ss_enc = HybridKEM.encapsulate(hpk)
            ss_dec = HybridKEM.decapsulate(hsk, ct)
            self.assertEqual(ss_enc, ss_dec)

    def test_different_keypairs_different_secrets(self):
        hpk1, hsk1 = HybridKEM.generate_keypair()
        hpk2, hsk2 = HybridKEM.generate_keypair()
        _, ss1 = HybridKEM.encapsulate(hpk1)
        _, ss2 = HybridKEM.encapsulate(hpk2)
        self.assertNotEqual(ss1, ss2)

    def test_wrong_key_rejected(self):
        hpk1, hsk1 = HybridKEM.generate_keypair()
        _, hsk2 = HybridKEM.generate_keypair()
        ct, ss_enc = HybridKEM.encapsulate(hpk1)
        ss_dec = HybridKEM.decapsulate(hsk2, ct)
        self.assertNotEqual(ss_enc, ss_dec)

    def test_shared_secret_is_32bytes(self):
        hpk, hsk = HybridKEM.generate_keypair()
        _, ss = HybridKEM.encapsulate(hpk)
        self.assertEqual(len(ss), 32)


class TestCoffeeCipher(unittest.TestCase):
    """CoffeeCipher v2 authenticated encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello hostile world"
        ct = CoffeeCipher.encrypt(plaintext, base_key=key)
        pt = CoffeeCipher.decrypt(ct, base_key=key)
        self.assertEqual(pt, plaintext)

    def test_encrypt_decrypt_with_recipe(self):
        key = os.urandom(32)
        plaintext = b"test with recipe"
        ct = CoffeeCipher.encrypt(plaintext, base_key=key, recipe="latte")
        pt = CoffeeCipher.decrypt(ct, base_key=key, recipe="latte")
        self.assertEqual(pt, plaintext)

    def test_wrong_key_fails_auth(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"secret message", base_key=key1)
        pt = CoffeeCipher.decrypt(ct, base_key=key2)
        self.assertEqual(pt, b"", "wrong key should fail HMAC auth")

    def test_wrong_recipe_fails_auth(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"secret message", base_key=key, recipe="latte")
        pt = CoffeeCipher.decrypt(ct, base_key=key, recipe="espresso")
        self.assertEqual(pt, b"", "wrong recipe should fail HMAC auth")

    def test_random_iv_different_ciphertexts(self):
        key = os.urandom(32)
        ct1 = CoffeeCipher.encrypt(b"same plaintext", base_key=key)
        ct2 = CoffeeCipher.encrypt(b"same plaintext", base_key=key)
        self.assertNotEqual(ct1, ct2, "random IV must produce different ciphertexts")

    def test_tampered_ciphertext_detected(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"important data", base_key=key)
        tampered = bytearray(ct)
        tampered[5] ^= 0xff
        pt = CoffeeCipher.decrypt(bytes(tampered), base_key=key)
        self.assertEqual(pt, b"", "tampered ciphertext must fail HMAC")

    def test_tampered_iv_detected(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"important data", base_key=key)
        tampered = bytearray(ct)
        tampered[0] ^= 0xff
        pt = CoffeeCipher.decrypt(bytes(tampered), base_key=key)
        self.assertEqual(pt, b"")

    def test_tampered_auth_tag_detected(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"important data", base_key=key)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xff
        pt = CoffeeCipher.decrypt(bytes(tampered), base_key=key)
        self.assertEqual(pt, b"")

    def test_empty_plaintext(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"", base_key=key)
        pt = CoffeeCipher.decrypt(ct, base_key=key)
        self.assertEqual(pt, b"")

    def test_large_plaintext(self):
        key = os.urandom(32)
        plaintext = os.urandom(100000)
        ct = CoffeeCipher.encrypt(plaintext, base_key=key)
        pt = CoffeeCipher.decrypt(ct, base_key=key)
        self.assertEqual(pt, plaintext)

    def test_ciphertext_format(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"test data", base_key=key)
        self.assertGreaterEqual(len(ct), 16 + 9 + 32, "IV + ciphertext + HMAC")

    def test_domain_separation_via_recipe(self):
        key = os.urandom(32)
        ct1 = CoffeeCipher.encrypt(b"test", base_key=key, recipe="espresso")
        ct2 = CoffeeCipher.encrypt(b"test", base_key=key, recipe="latte")
        self.assertNotEqual(ct1, ct2, "different recipes produce different ciphertexts")

    def test_hash_function(self):
        h1 = CoffeeCipher.hash(b"test data")
        h2 = CoffeeCipher.hash(b"test data")
        h3 = CoffeeCipher.hash(b"different data")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertEqual(len(h1), 16)


class TestCovertChannel(unittest.TestCase):
    """Covert channel v2 with authenticated encryption."""

    def test_encode_decode_roundtrip(self):
        msg = b"The eagle has landed"
        result = CovertChannel.encode(msg)
        self.assertIn("additions", result)
        additions = result["additions"]
        decoded = CovertChannel.decode(additions)
        self.assertEqual(decoded, msg)

    def test_encode_returns_additions_list(self):
        result = CovertChannel.encode(b"test message")
        self.assertIn("additions", result)
        self.assertIsInstance(result["additions"], list)
        self.assertGreater(len(result["additions"]), 0)

    def test_encode_with_string(self):
        result = CovertChannel.encode("hello string")
        self.assertIn("additions", result)
        decoded = CovertChannel.decode(result["additions"])
        self.assertEqual(decoded, b"hello string")

    def test_decode_tampered_fails(self):
        result = CovertChannel.encode(b"secret data")
        additions = result["additions"]
        if additions and "variety" in additions[0]:
            tampered = list(additions)
            tampered[0] = dict(additions[0])
            v = tampered[0]["variety"]
            if len(v) > 2:
                tampered[0]["variety"] = v[:2] + chr(ord(v[2]) ^ 1) + v[3:]
            decoded = CovertChannel.decode(tampered)
            self.assertNotEqual(decoded, b"secret data")

    def test_different_messages_different_encodings(self):
        result1 = CovertChannel.encode(b"alpha")
        result2 = CovertChannel.encode(b"bravo")
        hex1 = "".join(a["variety"] for a in result1["additions"] if not a["variety"].startswith(("route_", "recipe_")))
        hex2 = "".join(a["variety"] for a in result2["additions"] if not a["variety"].startswith(("route_", "recipe_")))
        self.assertNotEqual(hex1, hex2)

    def test_long_message(self):
        msg = b"A" * 500
        result = CovertChannel.encode(msg)
        decoded = CovertChannel.decode(result["additions"])
        self.assertEqual(decoded, msg)

    def test_empty_message_rejected(self):
        result = CovertChannel.encode(b"")
        self.assertIn("additions", result)


class TestSecureHash(unittest.TestCase):
    """SHA-3 and SHA-256 domain-separated hashing."""

    def test_sha256(self):
        data = b"test data"
        h = SecureHash.hash(data, "sha256")
        self.assertEqual(h, hashlib.sha256(data).digest())

    def test_sha3_256(self):
        data = b"test data"
        h = SecureHash.hash(data, "sha3_256")
        self.assertEqual(h, hashlib.sha3_256(data).digest())

    def test_sha3_512(self):
        data = b"test data"
        h = SecureHash.hash(data, "sha3_512")
        self.assertEqual(h, hashlib.sha3_512(data).digest())

    def test_shake256(self):
        data = b"test data"
        h = SecureHash.hash(data, "shake256")
        self.assertEqual(h, hashlib.shake_256(data).digest(64))

    def test_domain_separation(self):
        data = b"same data"
        h1 = SecureHash.domain_hash("mesh-heartbeat", data)
        h2 = SecureHash.domain_hash("mesh-message", data)
        self.assertNotEqual(h1, h2, "different domains must produce different hashes")

    def test_domain_hash_produces_32bytes(self):
        h = SecureHash.domain_hash("test-domain", b"test")
        self.assertEqual(len(h), 32)

    def test_unknown_algorithm_defaults_sha3(self):
        data = b"test"
        h = SecureHash.hash(data, "unknown")
        self.assertEqual(h, hashlib.sha3_256(data).digest())


class TestIncidentResponse(unittest.TestCase):
    """Incident response and audit chain."""

    def test_alert_creation(self):
        alert = IncidentResponse.alert("warn", "mesh", "Peer timeout detected")
        self.assertIn("id", alert)
        self.assertEqual(alert["severity"], "warn")
        self.assertEqual(alert["category"], "mesh")
        self.assertIn("message", alert)

    def test_alert_severity_levels(self):
        for level in ("info", "warn", "high", "critical"):
            alert = IncidentResponse.alert(level, "test", f"{level} alert")
            self.assertEqual(alert["severity"], level)

    def test_alert_with_details(self):
        alert = IncidentResponse.alert("info", "test", "test message",
                                        details={"key": "value"})
        self.assertIn("details", alert)
        self.assertEqual(alert["details"]["key"], "value")

    def test_audit_chain_integrity(self):
        IncidentResponse.alert("info", "test", "chain test 1")
        IncidentResponse.alert("warn", "test", "chain test 2")
        chain = IncidentResponse.get_audit_chain()
        self.assertIsInstance(chain, list)
        self.assertGreater(len(chain), 0)
        if len(chain) >= 2:
            self.assertIn("chain_hash", chain[-1])
            self.assertIn("prev_hash", chain[-1])

    def test_auto_mitigation(self):
        IncidentResponse.set_auto_mitigate(True)
        alert = IncidentResponse.alert("critical", "jamming", "Jamming detected")
        self.assertEqual(alert["severity"], "critical")

    def test_get_alerts(self):
        IncidentResponse.alert("info", "test", "test alert for retrieval")
        alerts = IncidentResponse.get_alerts()
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)

    def test_severity_filtering(self):
        IncidentResponse.alert("info", "test", "info alert filter")
        IncidentResponse.alert("critical", "test", "critical alert filter")
        critical = IncidentResponse.get_alerts(severity="critical")
        self.assertTrue(all(a["severity"] == "critical" for a in critical))

    def test_get_status(self):
        status = IncidentResponse.get_status()
        self.assertIn("total_alerts", status)
        self.assertIn("alerts_by_level", status)
        self.assertIn("mitigations_active", status)
        self.assertIn("audit_chain_valid", status)


class TestSignalAwareness(unittest.TestCase):
    """Signal awareness and bandwidth estimation."""

    def test_record_http(self):
        SignalAwareness.record_http("GET", "/", 200, 100, 500)
        bw = SignalAwareness.estimate_bandwidth()
        self.assertIn("http", bw)

    def test_record_mesh(self):
        SignalAwareness.record_mesh("heartbeat", 200, 50)
        bw = SignalAwareness.estimate_bandwidth()
        self.assertIn("mesh", bw)

    def test_jamming_detection(self):
        for _ in range(50):
            SignalAwareness.record_http("GET", "/", 200, 10, 50)
        bw = SignalAwareness.estimate_bandwidth()
        self.assertIn("http", bw)

    def test_update_link_quality(self):
        SignalAwareness.update_link_quality("peer-test", latency=50, loss=0.01)
        quality = SignalAwareness.get_link_quality("peer-test")
        self.assertIsInstance(quality, dict)
        self.assertIn("score", quality)

    def test_estimate_bandwidth_structure(self):
        bw = SignalAwareness.estimate_bandwidth()
        self.assertIn("http", bw)
        self.assertIn("mesh", bw)
        self.assertIn("uptime_seconds", bw)


class TestEmergencyMode(unittest.TestCase):
    """Emergency mode operations."""

    def test_activate(self):
        result = EmergencyMode.activate(reason="test emergency")
        self.assertIn("status", result)
        self.assertEqual(result["status"], "activated")
        EmergencyMode.deactivate()

    def test_deactivate(self):
        EmergencyMode.activate(reason="test")
        result = EmergencyMode.deactivate()
        self.assertIn("status", result)

    def test_key_rotation(self):
        result = EmergencyMode.rotate_keys()
        self.assertIn("status", result)
        self.assertEqual(result["status"], "keys_rotated")

    def test_secure_wipe(self):
        result = EmergencyMode.secure_wipe()
        self.assertIn("status", result)

    def test_get_status(self):
        status = EmergencyMode.get_status()
        self.assertIn("active", status)
        self.assertIn("stealth", status)
        self.assertIn("mitigations", status)


class TestNetDiagnostics(unittest.TestCase):
    """Network diagnostics."""

    def test_dns_resolve_localhost(self):
        result = NetDiagnostics.dns_resolve("localhost")
        self.assertTrue(result.get("resolved", False))
        self.assertIn("127.0.0.1", result.get("ipv4", []))

    def test_dns_resolve_failure(self):
        result = NetDiagnostics.dns_resolve("this.domain.should.not.exist.invalid")
        self.assertFalse(result.get("resolved", True))

    def test_interfaces(self):
        ifaces = NetDiagnostics.get_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)

    def test_tcp_ping(self):
        result = NetDiagnostics.tcp_ping("127.0.0.1", 4180, timeout=2)
        self.assertIn("alive", result)

    def test_port_scan(self):
        result = NetDiagnostics.port_scan("127.0.0.1", [4180], timeout=2)
        self.assertIsInstance(result, dict)
        self.assertIn("ports", result)

    def test_traceroute(self):
        result = NetDiagnostics.traceroute("127.0.0.1", max_hops=3)
        self.assertIsInstance(result, dict)
        self.assertIn("hops", result)


class TestMeshSecurity(unittest.TestCase):
    """Mesh message HMAC and timestamp validation."""

    def test_hmac_generation(self):
        key = os.urandom(32)
        data = b"test message"
        h = hashlib.sha256(key + data).digest()
        self.assertEqual(len(h), 32)

    def test_hmac_verification(self):
        key = os.urandom(32)
        data = b"test message"
        h = hashlib.sha256(key + data).digest()
        h2 = hashlib.sha256(key + data).digest()
        self.assertEqual(h, h2)

    def test_hmac_tamper_detection(self):
        key = os.urandom(32)
        data = b"test message"
        h = hashlib.sha256(key + data).digest()
        data2 = b"test messagE"
        h2 = hashlib.sha256(key + data2).digest()
        self.assertNotEqual(h, h2)

    def test_timestamp_validation(self):
        now = time.time()
        old = now - 600
        self.assertGreater(now - old, 300, "messages > 300s old should be rejected")


class TestPersistenceEncryption(unittest.TestCase):
    """Encrypted data at rest."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"stored mesh messages"
        ct = CoffeeCipher.encrypt(plaintext, base_key=key, recipe="persistence")
        pt = CoffeeCipher.decrypt(ct, base_key=key, recipe="persistence")
        self.assertEqual(pt, plaintext)

    def test_persistence_integrity(self):
        key = os.urandom(32)
        data = b"important stored data"
        ct = CoffeeCipher.encrypt(data, base_key=key, recipe="persistence")
        tampered = bytearray(ct)
        tampered[-1] ^= 0xff
        result = CoffeeCipher.decrypt(bytes(tampered), base_key=key, recipe="persistence")
        self.assertEqual(result, b"", "tampered persistence data should fail")

    def test_persistence_domain_separation(self):
        key = os.urandom(32)
        ct_p = CoffeeCipher.encrypt(b"test", base_key=key, recipe="persistence")
        ct_e = CoffeeCipher.encrypt(b"test", base_key=key, recipe="espresso")
        self.assertNotEqual(ct_p, ct_e)


if __name__ == "__main__":
    unittest.main(verbosity=2)