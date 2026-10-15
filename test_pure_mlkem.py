"""Tests for the standard-library-only KEM backend."""

import unittest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from pure_mlkem import PurePythonMLKEM


class TestPurePythonMLKEM(unittest.TestCase):
    def test_all_parameter_sizes_roundtrip_and_lengths(self):
        expected = {
            512: (800, 1632, 800),
            768: (1184, 2400, 1120),
            1024: (1568, 3168, 1600),
            2048: (3104, 6240, 3264),
            4096: (6176, 12384, 6848),
        }
        for size, lengths in expected.items():
            with self.subTest(size=size):
                kem = PurePythonMLKEM(size)
                public_key, secret_key = kem.keygen()
                ciphertext, sender_secret = kem.encapsulate(public_key)
                self.assertEqual((len(public_key), len(secret_key), len(ciphertext)), lengths)
                self.assertEqual(len(sender_secret), 32)
                self.assertEqual(sender_secret, kem.decapsulate(secret_key, ciphertext))

    def test_all_parameter_sizes_reject_tampering_and_wrong_keys(self):
        for size in (512, 768, 1024, 2048, 4096):
            with self.subTest(size=size):
                kem = PurePythonMLKEM(size)
                public_key, secret_key = kem.keygen()
                other_public_key, other_secret_key = kem.keygen()
                ciphertext, sender_secret = kem.encapsulate(public_key)
                tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
                self.assertNotEqual(sender_secret, kem.decapsulate(secret_key, tampered))
                self.assertNotEqual(sender_secret, kem.decapsulate(other_secret_key, ciphertext))

    def test_server_adapter_can_run_all_sizes_in_stdlib_mode(self):
        from server import DSA_ML_KEM, _ML_KEM_BACKENDS

        previous_backends = dict(_ML_KEM_BACKENDS)
        try:
            with patch.dict("os.environ", {"CPIP_ML_KEM_BACKEND": "stdlib"}):
                for size in (512, 768, 1024, 2048, 4096):
                    with self.subTest(size=size):
                        kem = DSA_ML_KEM(size)
                        public_key, secret_key = kem.keygen()
                        ciphertext, shared = kem.encapsulate(public_key)
                        self.assertEqual(shared, kem.decapsulate(secret_key, ciphertext))
                        self.assertEqual(_ML_KEM_BACKENDS[size], "stdlib")
        finally:
            _ML_KEM_BACKENDS.clear()
            _ML_KEM_BACKENDS.update(previous_backends)

    def test_extended_sizes_run_on_numpy_backend_when_installed(self):
        try:
            import numpy  # noqa: F401
        except ImportError:
            self.skipTest("NumPy acceleration is optional")
        from server import DSA_ML_KEM, _ML_KEM_BACKENDS

        previous_backends = dict(_ML_KEM_BACKENDS)
        try:
            with patch.dict("os.environ", {"CPIP_ML_KEM_BACKEND": "inf1del"}):
                for size in (2048, 4096):
                    with self.subTest(size=size):
                        kem = DSA_ML_KEM(size)
                        public_key, secret_key = kem.keygen()
                        ciphertext, shared = kem.encapsulate(public_key)
                        self.assertEqual(shared, kem.decapsulate(secret_key, ciphertext))
                        self.assertEqual(_ML_KEM_BACKENDS[size], "inf1del")
        finally:
            _ML_KEM_BACKENDS.clear()
            _ML_KEM_BACKENDS.update(previous_backends)

    def test_public_provider_registry_exposes_all_sizes_without_pqcrypto(self):
        from providers.kem import Kyber, get_pqc_kem

        original_backend = Kyber._backend
        try:
            with patch.dict("os.environ", {"CPIP_ML_KEM_BACKEND": "stdlib"}):
                Kyber._backend = None
                for size in (512, 768, 1024, 2048, 4096):
                    with self.subTest(size=size):
                        name = f"ml_kem_{size}" if size <= 1024 else f"1nf1d3l_kem_{size}"
                        provider = get_pqc_kem(name)
                        public_key, secret_key = provider.generate_keypair()
                        ciphertext, shared = provider.encapsulate(public_key)
                        self.assertEqual(shared, provider.decapsulate(secret_key, ciphertext))
        finally:
            Kyber._backend = original_backend

    def test_workbench_cli_keygen_runs_without_site_packages_for_all_sizes(self):
        repo = Path(__file__).resolve().parent
        for size in (512, 768, 1024, 2048, 4096):
            with self.subTest(size=size):
                algorithm = f"ml-kem-{size}" if size <= 1024 else f"1nf1d3l-kem-{size}"
                result = subprocess.run(
                    [sys.executable, "-S", "b4dm4n_cw.py", "keygen", "-a", algorithm],
                    cwd=repo, capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
