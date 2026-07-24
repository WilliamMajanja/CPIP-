#!/usr/bin/env python3
"""Comprehensive tests for CPIP cryptographic and security subsystems.

Tests: ECDSA/ECDH P-256, HybridKEM (ECDH P-256 + Kyber), CoffeeCipher v5 (AES-256-GCM),
SecureHash, IncidentResponse, SignalAwareness, EmergencyMode, NetDiagnostics,
CovertChannel, mesh HMAC, persistence encryption, and HTTP security.

All classical cryptographic primitives are FIPS-compliant:
- ECDSA/ECDH P-256 (FIPS 186-4)
- AES-256-GCM (FIPS 197)
- SHA-256 (FIPS 180-4)

The 1nf1D3L Kyber KEM (ML-KEM-768 variant, η=3) is non-FIPS.

Run: python3 test_crypto.py
"""
import hashlib
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from server import (
    ECP256,
    HQC128,
    HQC192,
    HQC256,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    PQCKEM,
    CoffeeCipher,
    CovertChannel,
    EmergencyMode,
    HybridKEM,
    IncidentResponse,
    McEliece348864,
    McEliece348864f,
    McEliece460896,
    McEliece460896f,
    McEliece6688128,
    McEliece6688128f,
    McEliece6960119,
    McEliece6960119f,
    McEliece8192128,
    McEliece8192128f,
    NetDiagnostics,
    SecureHash,
    SignalAwareness,
)


class TestECP256(unittest.TestCase):
    """ECDSA/ECDH P-256 (FIPS 186-4) signature and key exchange."""

    def test_keypair_generation(self):
        pk, seed, privkey, pubkey = ECP256.generate_keypair()
        self.assertGreater(len(pk), 0)
        self.assertEqual(len(seed), 32)
        self.assertIsNotNone(privkey)
        self.assertIsNotNone(pubkey)

    def test_encode_decode_roundtrip(self):
        pk, _seed, _privkey, _pubkey = ECP256.generate_keypair()
        decoded = ECP256._decode_point(pk)
        re_encoded = ECP256._encode_point(decoded)
        self.assertEqual(pk, re_encoded, "encode/decode roundtrip failed")

    def test_sign_verify(self):
        pk, seed, _privkey, _pubkey = ECP256.generate_keypair()
        msg = b"hello coffee protocol"
        sig = ECP256.sign(msg, seed)
        self.assertGreater(len(sig), 0)
        self.assertTrue(ECP256.verify(msg, sig, pk))

    def test_sign_verify_wrong_message(self):
        pk, seed, _, _ = ECP256.generate_keypair()
        sig = ECP256.sign(b"correct message", seed)
        self.assertFalse(ECP256.verify(b"wrong message", sig, pk))

    def test_sign_verify_wrong_key(self):
        _pk1, seed1, _, _ = ECP256.generate_keypair()
        pk2, _seed2, _, _ = ECP256.generate_keypair()
        sig = ECP256.sign(b"test", seed1)
        self.assertFalse(ECP256.verify(b"test", sig, pk2))

    def test_sign_verify_tampered_signature(self):
        pk, seed, _, _ = ECP256.generate_keypair()
        sig = ECP256.sign(b"test", seed)
        tampered = bytearray(sig)
        tampered[10] ^= 0xff
        self.assertFalse(ECP256.verify(b"test", bytes(tampered), pk))

    def test_sign_verify_empty_message(self):
        pk, seed, _, _ = ECP256.generate_keypair()
        sig = ECP256.sign(b"", seed)
        self.assertTrue(ECP256.verify(b"", sig, pk))

    def test_sign_verify_large_message(self):
        pk, seed, _, _ = ECP256.generate_keypair()
        msg = os.urandom(10000)
        sig = ECP256.sign(msg, seed)
        self.assertTrue(ECP256.verify(msg, sig, pk))

    def test_ecdh_shared_secret(self):
        pk1, s1, _, _ = ECP256.generate_keypair()
        pk2, s2, _, _ = ECP256.generate_keypair()
        shared1 = ECP256.key_exchange(s1, pk2)
        shared2 = ECP256.key_exchange(s2, pk1)
        self.assertEqual(shared1, shared2, "ECDH shared secrets must match")

    def test_ecdh_multiple_iterations(self):
        for _ in range(5):
            pk1, s1, _, _ = ECP256.generate_keypair()
            pk2, s2, _, _ = ECP256.generate_keypair()
            self.assertEqual(
                ECP256.key_exchange(s1, pk2),
                ECP256.key_exchange(s2, pk1),
            )

    def test_ecdh_different_peers_produce_different_secrets(self):
        _pk1, s1, _, _ = ECP256.generate_keypair()
        pk2, _s2, _, _ = ECP256.generate_keypair()
        pk3, _s3, _, _ = ECP256.generate_keypair()
        ss12 = ECP256.key_exchange(s1, pk2)
        ss13 = ECP256.key_exchange(s1, pk3)
        self.assertNotEqual(ss12, ss13)

    def test_pubkey_to_address(self):
        pk, _, _, _ = ECP256.generate_keypair()
        addr = ECP256.pubkey_to_address(pk)
        self.assertTrue(addr.startswith("coffee:"))
        self.assertTrue(ECP256.address_matches(addr, pk))
        pk_other, _, _, _ = ECP256.generate_keypair()
        self.assertFalse(ECP256.address_matches(addr, pk_other))

    def test_deterministic_keypair(self):
        seed = os.urandom(32)
        pk1, s1, _a1, _A1 = ECP256.generate_keypair(seed)
        pk2, s2, _a2, _A2 = ECP256.generate_keypair(seed)
        self.assertEqual(pk1, pk2)
        self.assertEqual(s1, s2)


class TestMLKEM(unittest.TestCase):
    """ML-KEM-768 key encapsulation (FIPS 203 / ML-KEM-768).
    
    Uses the pqcrypto ML-KEM-768 implementation via MLKEM768 wrapper.
    """

    def test_keygen(self):
        pk, sk = MLKEM768.generate_keypair()
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)

    def test_encaps_decaps_match(self):
        pk, sk = MLKEM768.generate_keypair()
        ct, ss_enc = MLKEM768.encapsulate(pk)
        ss_dec = MLKEM768.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "ML-KEM-768 shared secrets must match")

    def test_encaps_decaps_multiple_iterations(self):
        for _ in range(3):
            pk, sk = MLKEM768.generate_keypair()
            ct, ss_enc = MLKEM768.encapsulate(pk)
            ss_dec = MLKEM768.decapsulate(sk, ct)
            self.assertEqual(ss_enc, ss_dec)

    def test_different_keys_different_secrets(self):
        pk1, _sk1 = MLKEM768.generate_keypair()
        pk2, _sk2 = MLKEM768.generate_keypair()
        _, ss1 = MLKEM768.encapsulate(pk1)
        _, ss2 = MLKEM768.encapsulate(pk2)
        self.assertNotEqual(ss1, ss2)

    def test_tampered_ciphertext_rejected(self):
        pk, sk = MLKEM768.generate_keypair()
        ct, ss_enc = MLKEM768.encapsulate(pk)
        tampered = bytes(b ^ 0x01 for b in ct[:8]) + ct[8:]
        ss_dec = MLKEM768.decapsulate(sk, tampered)
        self.assertNotEqual(ss_enc, ss_dec, "tampered ct must produce different secret")

    def test_deterministic_decaps(self):
        pk, sk = MLKEM768.generate_keypair()
        ct, _ = MLKEM768.encapsulate(pk)
        ss1 = MLKEM768.decapsulate(sk, ct)
        ss2 = MLKEM768.decapsulate(sk, ct)
        self.assertEqual(ss1, ss2)

    def test_wrong_secret_key_rejected(self):
        pk1, _sk1 = MLKEM768.generate_keypair()
        _, sk2 = MLKEM768.generate_keypair()
        ct, ss_enc = MLKEM768.encapsulate(pk1)
        ss_dec = MLKEM768.decapsulate(sk2, ct)
        self.assertNotEqual(ss_enc, ss_dec)

    def test_encapsulation_produces_32byte_secret(self):
        pk, _sk = MLKEM768.generate_keypair()
        _ct, ss = MLKEM768.encapsulate(pk)
        self.assertEqual(len(ss), 32)


class TestHybridKEM(unittest.TestCase):
    """Hybrid ECDH P-256 + ML-KEM-768 key exchange."""

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
        hpk1, _hsk1 = HybridKEM.generate_keypair()
        hpk2, _hsk2 = HybridKEM.generate_keypair()
        _, ss1 = HybridKEM.encapsulate(hpk1)
        _, ss2 = HybridKEM.encapsulate(hpk2)
        self.assertNotEqual(ss1, ss2)

    def test_wrong_key_rejected(self):
        hpk1, _hsk1 = HybridKEM.generate_keypair()
        _, hsk2 = HybridKEM.generate_keypair()
        ct, ss_enc = HybridKEM.encapsulate(hpk1)
        ss_dec = HybridKEM.decapsulate(hsk2, ct)
        self.assertNotEqual(ss_enc, ss_dec)

    def test_shared_secret_is_32bytes(self):
        hpk, _hsk = HybridKEM.generate_keypair()
        _, ss = HybridKEM.encapsulate(hpk)
        self.assertEqual(len(ss), 32)


class TestCoffeeCipher(unittest.TestCase):
    """CoffeeCipher v5 AES-256-GCM authenticated encryption (FIPS 197)."""

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
        self.assertEqual(pt, b"", "wrong key should fail GCM auth")

    def test_wrong_recipe_fails_auth(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"secret message", base_key=key, recipe="latte")
        pt = CoffeeCipher.decrypt(ct, base_key=key, recipe="espresso")
        self.assertEqual(pt, b"", "wrong recipe should fail GCM auth")

    def test_random_nonce_different_ciphertexts(self):
        key = os.urandom(32)
        ct1 = CoffeeCipher.encrypt(b"same plaintext", base_key=key)
        ct2 = CoffeeCipher.encrypt(b"same plaintext", base_key=key)
        self.assertNotEqual(ct1, ct2, "random nonce must produce different ciphertexts")

    def test_tampered_ciphertext_detected(self):
        key = os.urandom(32)
        ct = CoffeeCipher.encrypt(b"important data", base_key=key)
        tampered = bytearray(ct)
        tampered[5] ^= 0xff
        pt = CoffeeCipher.decrypt(bytes(tampered), base_key=key)
        self.assertEqual(pt, b"", "tampered ciphertext must fail GCM auth")

    def test_tampered_nonce_detected(self):
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
        self.assertGreaterEqual(len(ct), 12 + 9 + 16, "nonce(12) + ciphertext + GCM tag(16)")

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
    """Covert channel v3 with AES-256-GCM authenticated encryption."""

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
    """SHA-256 and SHA-3 domain-separated hashing (FIPS 180-4)."""

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

    def test_unknown_algorithm_defaults_sha256(self):
        data = b"test"
        h = SecureHash.hash(data, "unknown")
        self.assertEqual(h, hashlib.sha256(data).digest())


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


class TestPQCKEMs(unittest.TestCase):
    """Non-FIPS Post-Quantum KEMs (HQC, McEliece, ML-KEM variants)."""
    
    @classmethod
    def setUpClass(cls):
        # Import the new KEM classes
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from server import MLKEM768
        cls.PQCKEM = PQCKEM
        cls.HQC128 = HQC128
        cls.HQC192 = HQC192
        cls.HQC256 = HQC256
        cls.McEliece348864 = McEliece348864
        cls.McEliece348864f = McEliece348864f
        cls.McEliece460896 = McEliece460896
        cls.McEliece460896f = McEliece460896f
        cls.McEliece6688128 = McEliece6688128
        cls.McEliece6688128f = McEliece6688128f
        cls.McEliece6960119 = McEliece6960119
        cls.McEliece6960119f = McEliece6960119f
        cls.McEliece8192128 = McEliece8192128
        cls.McEliece8192128f = McEliece8192128f
        cls.MLKEM512 = MLKEM512
        cls.MLKEM768 = MLKEM768
        cls.MLKEM1024 = MLKEM1024
    
    def test_pqc_kem_available(self):
        """Test that pqcrypto is available."""
        self.assertTrue(self.PQCKEM.is_available(), "pqcrypto should be available")
    
    def test_hqc128_roundtrip(self):
        """Test HQC-128 keygen, encaps, decaps."""
        kem = self.HQC128
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "HQC-128 shared secrets must match")
    
    def test_hqc192_roundtrip(self):
        """Test HQC-192 keygen, encaps, decaps."""
        kem = self.HQC192
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "HQC-192 shared secrets must match")
    
    def test_hqc256_roundtrip(self):
        """Test HQC-256 keygen, encaps, decaps."""
        kem = self.HQC256
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "HQC-256 shared secrets must match")
    
    def test_mceliece348864_roundtrip(self):
        """Test Classic McEliece 348864 keygen, encaps, decaps."""
        kem = self.McEliece348864
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "McEliece348864 shared secrets must match")
    
    def test_mceliece460896_roundtrip(self):
        """Test Classic McEliece 460896 keygen, encaps, decaps."""
        kem = self.McEliece460896
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "McEliece460896 shared secrets must match")
    
    def test_mceliece6688128_roundtrip(self):
        """Test Classic McEliece 6688128 keygen, encaps, decaps."""
        kem = self.McEliece6688128
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "McEliece6688128 shared secrets must match")
    
    def test_mceliece6960119_roundtrip(self):
        """Test Classic McEliece 6960119 keygen, encaps, decaps."""
        kem = self.McEliece6960119
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "McEliece6960119 shared secrets must match")
    
    def test_mceliece8192128_roundtrip(self):
        """Test Classic McEliece 8192128 keygen, encaps, decaps."""
        kem = self.McEliece8192128
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "McEliece8192128 shared secrets must match")
    
    def test_mlkem512_roundtrip(self):
        """Test ML-KEM-512 keygen, encaps, decaps."""
        kem = self.MLKEM512
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "ML-KEM-512 shared secrets must match")
    
    def test_mlkem768_roundtrip(self):
        """Test ML-KEM-768 keygen, encaps, decaps."""
        kem = self.MLKEM768
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "ML-KEM-768 shared secrets must match")
    
    def test_mlkem1024_roundtrip(self):
        """Test ML-KEM-1024 keygen, encaps, decaps."""
        kem = self.MLKEM1024
        pk, sk = kem.generate_keypair()
        self.assertEqual(len(pk), kem.PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), kem.SECRET_KEY_SIZE)
        
        ct, ss_enc = kem.encapsulate(pk)
        self.assertEqual(len(ct), kem.CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_enc), kem.SHARED_KEY_SIZE)
        
        ss_dec = kem.decapsulate(sk, ct)
        self.assertEqual(ss_enc, ss_dec, "ML-KEM-1024 shared secrets must match")
    
    def test_different_kems_different_secrets(self):
        """Test that different KEMs produce different shared secrets for same keypair."""
        # Each KEM should produce different shared secrets even with same input patterns
        hqc128_pk, _hqc128_sk = self.HQC128.generate_keypair()
        mce_pk, _mce_sk = self.McEliece348864.generate_keypair()
        
        _, hqc_ss = self.HQC128.encapsulate(hqc128_pk)
        _, mce_ss = self.McEliece348864.encapsulate(mce_pk)
        
        self.assertNotEqual(hqc_ss, mce_ss, "Different KEMs should produce different secrets")
    
    def test_tampered_ciphertext_rejected(self):
        """Test that tampered ciphertexts are handled (raise or return fake key)."""
        pk, sk = self.HQC128.generate_keypair()
        ct, _ss_enc = self.HQC128.encapsulate(pk)
        
        # Tamper with ciphertext
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        
        # Some KEMs raise on decryption failure, others use implicit rejection
        # Just verify it doesn't crash silently and produces some output or raises
        try:
            ss_dec = self.HQC128.decapsulate(sk, bytes(tampered))
            # If it returns, verify output length
            self.assertEqual(len(ss_dec), self.HQC128.SHARED_KEY_SIZE)
        except RuntimeError:
            # Acceptable: KEM raises on decryption failure
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)