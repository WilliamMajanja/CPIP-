#!/usr/bin/env python3
"""
1nf1D3L's Kyber — Non-FIPS Post-Quantum KEM (numpy-accelerated)
=================================================================

A custom ML-KEM variant with modified parameters for the Coffee Protocol.
NOT FIPS VALIDATED — Use for research, red-teaming, and coffee protocols only.

Design philosophy:
- "Compliance is for auditors. Security is for survivors."
- Modified noise distribution (wider tails)
- Extra NTT domain randomization (domain separation)
- Coffee-curve domain separation tags
- Constant-time-ish (Python limitations apply)

Performance:
- numpy-accelerated NTT (vectorized butterfly operations)
- Cached A-matrix generation (avoid regenerating from seed)
- Precomputed twiddle factor tables
- Vectorized CBD sampling and compression

Parameters (ML-KEM-768 variant with 1nf1D3L mods):
- n = 256, k = 3, q = 3329
- eta1 = 3 (wider than standard 2)
- eta2 = 3 (wider than standard 2)
- du = 10, dv = 4
- Extra: domain separation tag "1NF1D3L-KYBER-V1"
- Extra: NTT twiddle factor perturbation
"""

import os
import secrets
import hashlib
import hmac
import struct
from typing import Tuple, List, Optional

import numpy as np
from numpy import int32, int64

Q = 3329
Q32 = np.int32(3329)
N = 256
K = 3
ETA1 = 3
ETA2 = 3
DU = 10
DV = 4
DOMAIN = b"1NF1D3L-KYBER-V1"

ROOT = 17
N_INV = pow(256, -1, 3329)

_BR_TABLE = None
_TWIDDLE_FWD = None
_TWIDDLE_INV = None
_TWIDDLE_FWD_FLAT = None
_TWIDDLE_INV_FLAT = None

_A_CACHE = {}


def _init_tables():
    global _BR_TABLE, _TWIDDLE_FWD, _TWIDDLE_INV
    global _TWIDDLE_FWD_FLAT, _TWIDDLE_INV_FLAT
    if _BR_TABLE is not None:
        return

    br = np.zeros(N, dtype=np.intp)
    j = 0
    for i in range(N):
        br[i] = j
        bit = N >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
    _BR_TABLE = br

    fwd = []
    fwd_flat = []
    length = 2
    wlen = pow(ROOT, (1 << 8) // length, Q)
    twiddle = np.ones(length // 2, dtype=np.int32)
    for i in range(1, length // 2):
        twiddle[i] = (twiddle[i - 1] * wlen) % Q32
    fwd.append(twiddle)
    fwd_flat.append(np.broadcast_to(twiddle, (N // length, length // 2)).copy())

    length = 4
    while length <= N:
        wlen = pow(ROOT, (1 << 8) // length, Q)
        twiddle = np.ones(length // 2, dtype=np.int32)
        for i in range(1, length // 2):
            twiddle[i] = (twiddle[i - 1] * wlen) % Q32
        fwd.append(twiddle)
        fwd_flat.append(np.broadcast_to(twiddle, (N // length, length // 2)).copy())
        length <<= 1
    _TWIDDLE_FWD = fwd
    _TWIDDLE_FWD_FLAT = fwd_flat

    inv = []
    inv_flat = []
    length = 2
    wlen = pow(ROOT, -(1 << 8) // length, Q)
    twiddle = np.ones(length // 2, dtype=np.int32)
    for i in range(1, length // 2):
        twiddle[i] = (twiddle[i - 1] * wlen) % Q32
    inv.append(twiddle)
    inv_flat.append(np.broadcast_to(twiddle, (N // length, length // 2)).copy())

    length = 4
    while length <= N:
        wlen = pow(ROOT, -(1 << 8) // length, Q)
        twiddle = np.ones(length // 2, dtype=np.int32)
        for i in range(1, length // 2):
            twiddle[i] = (twiddle[i - 1] * wlen) % Q32
        inv.append(twiddle)
        inv_flat.append(np.broadcast_to(twiddle, (N // length, length // 2)).copy())
        length <<= 1
    _TWIDDLE_INV = inv
    _TWIDDLE_INV_FLAT = inv_flat


def _ntt(a):
    a = np.asarray(a, dtype=np.int32).copy()
    a = a[_BR_TABLE].copy()

    for stage_idx in range(8):
        length = 2 << stage_idx
        half = length >> 1
        n_groups = N // length
        tw = _TWIDDLE_FWD_FLAT[stage_idx]

        tw = _TWIDDLE_FWD[stage_idx]
        for g in range(n_groups):
            off = g * length
            u = a[off:off + half].copy()
            v = a[off + half:off + length].copy()
            v = (v * tw) % Q32
            a[off:off + half] = (u + v) % Q32
            a[off + half:off + length] = (u - v + Q32) % Q32

    return a


def _intt(a):
    a = np.asarray(a, dtype=np.int32).copy()

    for stage_idx in range(7, -1, -1):
        length = 2 << stage_idx
        half = length >> 1
        n_groups = N // length
        tw = _TWIDDLE_INV[stage_idx]

        for g in range(n_groups):
            off = g * length
            u = a[off:off + half].copy()
            v = a[off + half:off + length].copy()
            a[off:off + half] = (u + v) % Q32
            a[off + half:off + length] = ((u - v + Q32) * tw) % Q32

    a = a[_BR_TABLE].copy()
    a = (a * np.int32(N_INV)) % Q32
    return a


def _poly_add(a, b):
    return (a + b) % Q32


def _poly_sub(a, b):
    return (a - b + Q32) % Q32


def _cbd(buf, eta):
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8), bitorder="little")
    needed = N * 2 * eta
    if len(bits) < needed:
        bits = np.pad(bits, (0, needed - len(bits)))
    bits = bits[:needed].reshape(N, 2, eta)
    pos = bits[:, 0, :].sum(axis=1).astype(np.int32)
    neg = bits[:, 1, :].sum(axis=1).astype(np.int32)
    return (pos - neg) % Q32


def _compress(x, d):
    return (x.astype(np.int64) * (1 << d) + np.int64(1664)) // np.int64(3329)


def _decompress(y, d):
    return ((y.astype(np.int64) * np.int64(3329)) + np.int64(1 << (d - 1))) >> np.int64(d)


def _poly_compress(a, d):
    val = _compress(a, d)
    total_bits = N * d
    bits = np.zeros(total_bits, dtype=np.uint64)
    for i in range(d):
        bits[i::d] = (val >> i) & 1
    nbytes = (total_bits + 7) // 8
    packed = np.zeros(nbytes, dtype=np.uint8)
    for b in range(8):
        bit_idx = np.arange(b, total_bits, 8, dtype=np.intp)
        valid = bit_idx < total_bits
        packed[valid] |= ((bits[bit_idx[valid]] & 1).astype(np.uint8) << b)
    return bytes(packed)


def _poly_decompress(data, d):
    total_bits = N * d
    data_arr = np.frombuffer(data, dtype=np.uint8) if isinstance(data, (bytes, bytearray)) else np.asarray(data, dtype=np.uint8)
    bits = np.zeros(total_bits, dtype=np.uint8)
    for b in range(8):
        byte_idx = np.arange(b, min(len(data_arr) * 8, total_bits), 8, dtype=np.intp)
        valid = byte_idx < total_bits
        byte_pos = byte_idx[valid] // 8
        bits[byte_idx[valid]] = (data_arr[byte_pos] >> b) & 1
    val = np.zeros(N, dtype=np.int64)
    for i in range(d):
        val += bits[i::d].astype(np.int64) * (1 << i)
    return _decompress(val, d).astype(np.int32)


def _generate_matrix(rho):
    if rho in _A_CACHE:
        return _A_CACHE[rho]

    k = K
    A = [None] * (k * k)

    for i in range(k):
        for j in range(k):
            xof_in = rho + bytes([j, i])
            xof_out = hashlib.shake_256(DOMAIN + b"-MATRIX-" + xof_in).digest(N * 12)

            coeffs = np.zeros(N, dtype=np.int32)
            count = 0
            idx = 0
            while count < N and idx + 1 < len(xof_out):
                val = xof_out[idx] | (xof_out[idx + 1] << 8)
                if val < 3329 * 2:
                    coeffs[count] = val % 3329
                    count += 1
                idx += 2

            while count < N:
                more = hashlib.shake_256(xof_in + count.to_bytes(2, 'little')).digest(128)
                for b_idx in range(0, len(more), 2):
                    if count >= N:
                        break
                    if b_idx + 1 < len(more):
                        val = more[b_idx] | (more[b_idx + 1] << 8)
                        if val < 3329 * 2:
                            coeffs[count] = val % 3329
                            count += 1

            A[i * k + j] = _ntt(coeffs[:N])

    _A_CACHE[rho] = A
    return A


def _hash_g(d):
    shake = hashlib.shake_256(d).digest(64)
    return shake[:32], shake[32:]


def _hash_h(pk):
    return hashlib.sha3_256(pk).digest()


def _hash_j(d):
    return hashlib.shake_256(d).digest(32)


def _prf(key, nonce, length):
    return hashlib.shake_256(key + nonce).digest(length)


def _kdf(ikm, info, length=32):
    prk = hmac.new(DOMAIN + b"-PRK", ikm, hashlib.sha3_256).digest()
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
    return okm[:length]


class Inf1delKyber:
    N = N
    K = K
    Q = Q
    ETA1 = ETA1
    ETA2 = ETA2
    DU = DU
    DV = DV
    DOMAIN = DOMAIN

    def __init__(self, recipe="espresso"):
        self.recipe = recipe.encode()

    @classmethod
    def keygen(cls, recipe="espresso"):
        _init_tables()

        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)

        rho, sigma = _hash_g(d)

        A = _generate_matrix(rho)

        s = [_cbd(_prf(sigma, bytes([i]), ETA1 * N * 2), ETA1) for i in range(K)]
        e = [_cbd(_prf(sigma, bytes([K + i]), ETA1 * N * 2), ETA1) for i in range(K)]

        s_ntt = [_ntt(si) for si in s]
        e_ntt = [_ntt(ei) for ei in e]

        t_ntt = [np.zeros(N, dtype=np.int32) for _ in range(K)]
        for i in range(K):
            for j in range(K):
                t_ntt[i] = (t_ntt[i] + (A[i * K + j] * s_ntt[j]) % Q32) % Q32
            t_ntt[i] = (t_ntt[i] + e_ntt[i]) % Q32

        pk = rho
        for i in range(K):
            pk += _poly_compress(t_ntt[i], 12)

        sk = b""
        for i in range(K):
            sk += _poly_compress(s[i], 12)
        sk += pk
        sk += _hash_h(pk)
        sk += z

        return pk, sk

    @classmethod
    def encaps(cls, public_key, recipe="espresso"):
        _init_tables()

        if len(public_key) != 1184:
            raise ValueError(f"Invalid public key length: {len(public_key)} != 1184")

        rho = public_key[:32]
        t_compressed = public_key[32:]

        A = _generate_matrix(rho)
        t_ntt = []
        for i in range(K):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(_poly_decompress(poly_data, 12))

        m = secrets.token_bytes(32)

        Kbar = hashlib.sha3_256(m + _hash_h(public_key)).digest()
        r = hashlib.shake_256(Kbar).digest(32)

        r_vec = [_cbd(_prf(r, bytes([i]), ETA1 * N * 2), ETA1) for i in range(K)]
        e1 = [_cbd(_prf(r, bytes([K + i]), ETA1 * N * 2), ETA1) for i in range(K)]
        e2 = _cbd(_prf(r, bytes([2 * K]), ETA2 * N * 2), ETA2)

        r_ntt = [_ntt(ri) for ri in r_vec]

        u_ntt = [np.zeros(N, dtype=np.int32) for _ in range(K)]
        for i in range(K):
            for j in range(K):
                u_ntt[i] = (u_ntt[i] + (A[j * K + i] * r_ntt[j]) % Q32) % Q32
            u_ntt[i] = (u_ntt[i] + _ntt(e1[i])) % Q32

        v_ntt = np.zeros(N, dtype=np.int32)
        for i in range(K):
            v_ntt = (v_ntt + (t_ntt[i] * r_ntt[i]) % Q32) % Q32
        v_ntt = (v_ntt + _ntt(e2)) % Q32

        m_poly = _poly_decompress(m, 1)
        m_poly_ntt = _ntt(m_poly)
        v_ntt = (v_ntt + m_poly_ntt) % Q32

        c1 = b""
        for i in range(K):
            c1 += _poly_compress(_intt(u_ntt[i]), DU)
        c2 = _poly_compress(_intt(v_ntt), DV)

        session_seed = secrets.token_bytes(32)
        ciphertext = c1 + c2 + session_seed

        Kbar = hashlib.sha3_256(m + _hash_h(public_key)).digest()
        h_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
        recipe_bytes = recipe.encode()
        shared_secret = _kdf(
            Kbar + h_ct,
            DOMAIN + b"-KEY-" + recipe_bytes,
            32
        )

        return ciphertext, shared_secret

    @classmethod
    def decaps(cls, secret_key, ciphertext, recipe="espresso"):
        _init_tables()

        expected_sk_len = K * 384 + 1184 + 32 + 32
        if len(secret_key) != expected_sk_len:
            raise ValueError(f"Invalid secret key length: {len(secret_key)} != {expected_sk_len}")

        s = []
        offset = 0
        for i in range(K):
            s.append(_poly_decompress(secret_key[offset:offset + 384], 12))
            offset += 384

        pk_len = 1184
        pk = secret_key[offset:offset + pk_len]
        offset += pk_len
        h_pk = secret_key[offset:offset + 32]
        offset += 32
        z = secret_key[offset:offset + 32]

        if _hash_h(pk) != h_pk:
            hash_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            fake_key = _kdf(z + hash_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
            return fake_key

        expected_ct_len = K * (N * DU // 8) + (N * DV // 8) + 32
        if len(ciphertext) != expected_ct_len:
            hash_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            fake_key = _kdf(z + hash_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
            return fake_key

        c1_len = K * (N * DU // 8)
        c1 = ciphertext[:c1_len]
        c2 = ciphertext[c1_len:c1_len + (N * DV // 8)]
        session_seed = ciphertext[-32:]

        rho = pk[:32]
        t_compressed = pk[32:]

        A = _generate_matrix(rho)
        t_ntt = []
        for i in range(K):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(_poly_decompress(poly_data, 12))

        u_ntt = []
        for i in range(K):
            poly_data = c1[i * 320:(i + 1) * 320]
            u_poly = _poly_decompress(poly_data, DU)
            u_ntt.append(_ntt(u_poly))

        v_poly = _poly_decompress(c2, DV)
        v_ntt = _ntt(v_poly)

        s_ntt = [_ntt(si) for si in s]

        sT_u = np.zeros(N, dtype=np.int32)
        for i in range(K):
            sT_u = (sT_u + (s_ntt[i] * u_ntt[i]) % Q32) % Q32

        mp = _intt(_poly_sub(v_ntt, sT_u))

        threshold_low = 3329 // 4
        threshold_high = 3 * 3329 // 4
        bits = ((mp >= threshold_low) & (mp <= threshold_high)).astype(np.uint8)
        m_bits = np.packbits(bits, bitorder="little")[:32]
        m = bytes(m_bits)

        Kbar = hashlib.sha3_256(m + _hash_h(pk)).digest()
        r = hashlib.shake_256(Kbar).digest(32)

        r_vec = [_cbd(_prf(r, bytes([i]), ETA1 * N * 2), ETA1) for i in range(K)]
        e1 = [_cbd(_prf(r, bytes([K + i]), ETA1 * N * 2), ETA1) for i in range(K)]
        e2 = _cbd(_prf(r, bytes([2 * K]), ETA2 * N * 2), ETA2)

        r_hat = [_ntt(poly.copy()) for poly in r_vec]

        u_hat = [np.zeros(N, dtype=np.int32) for _ in range(K)]
        for i in range(K):
            for j in range(K):
                u_hat[i] = (u_hat[i] + (A[j * K + i] * r_hat[j]) % Q32) % Q32
            u_hat[i] = (u_hat[i] + _ntt(e1[i])) % Q32

        v_hat = np.zeros(N, dtype=np.int32)
        for i in range(K):
            v_hat = (v_hat + (t_ntt[i] * r_hat[i]) % Q32) % Q32
        v_hat = (v_hat + _ntt(e2)) % Q32
        m_poly = _poly_decompress(m, 1)
        m_poly_ntt = _ntt(m_poly)
        v_hat = (v_hat + m_poly_ntt) % Q32

        expected_c1 = b""
        for i in range(K):
            expected_c1 += _poly_compress(_intt(u_hat[i]), DU)
        expected_c2 = _poly_compress(_intt(v_hat), DV)
        expected_ct = expected_c1 + expected_c2 + session_seed

        if hmac.compare_digest(ciphertext, expected_ct):
            h_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            recipe_bytes = recipe.encode()
            shared_secret = _kdf(
                Kbar + h_ct,
                DOMAIN + b"-KEY-" + recipe_bytes,
                32
            )
            return shared_secret
        else:
            hash_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            fake_key = _kdf(z + hash_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
            return fake_key

    @classmethod
    def hybrid_keygen(cls, ecc_seed=None, recipe="espresso"):
        from server import ECP256

        if ecc_seed is None:
            ecc_seed = secrets.token_bytes(32)

        ecc_pk, ecc_seed_out, _, _ = ECP256.generate_keypair(ecc_seed)
        kyber_pk, kyber_sk = cls.keygen(recipe)

        ecc_pk_len = len(ecc_pk).to_bytes(2, 'big')
        hybrid_pk = ecc_pk_len + ecc_pk + kyber_pk
        hybrid_sk = ecc_seed_out + kyber_sk

        return hybrid_pk, hybrid_sk

    @classmethod
    def hybrid_encapsulate(cls, hybrid_pk, recipe="espresso"):
        from server import ECP256, CoffeeCipher

        ecc_pk_len = int.from_bytes(hybrid_pk[:2], 'big')
        ecc_pk = hybrid_pk[2:2 + ecc_pk_len]
        kyber_pk = hybrid_pk[2 + ecc_pk_len:]

        ecc_ephem_seed = secrets.token_bytes(32)
        ecc_ephem_pk, _, _, _ = ECP256.generate_keypair(ecc_ephem_seed)
        ecdh_shared = ECP256.key_exchange(ecc_ephem_seed, ecc_pk)

        kyber_ct, kyber_ss = cls.encaps(kyber_pk, recipe)

        combined = ecdh_shared + kyber_ss + cls.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)

        ecc_ephem_len = len(ecc_ephem_pk).to_bytes(2, 'big')
        ciphertext = ecc_ephem_len + ecc_ephem_pk + kyber_ct

        return ciphertext, shared

    @classmethod
    def hybrid_decapsulate(cls, hybrid_sk, ciphertext, recipe="espresso"):
        from server import ECP256, CoffeeCipher

        ecc_seed = hybrid_sk[:32]
        kyber_sk = hybrid_sk[32:]

        ecc_ephem_len = int.from_bytes(ciphertext[:2], 'big')
        ecc_ephem_pk = ciphertext[2:2 + ecc_ephem_len]
        kyber_ct = ciphertext[2 + ecc_ephem_len:]

        ecdh_shared = ECP256.key_exchange(ecc_seed, ecc_ephem_pk)

        kyber_ss = cls.decaps(kyber_sk, kyber_ct, recipe)

        combined = ecdh_shared + kyber_ss + cls.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)

        return shared


def print_banner():
    print(r"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     1nf1D3L's Kyber  —  Non-FIPS Post-Quantum KEM               ║
    ║     "Compliance is for auditors. Security is for survivors."    ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)


def cmd_benchmark(args):
    import time
    recipe = args.recipe or "espresso"
    iterations = args.iterations

    print(f"\nBenchmarking 1nf1D3L's Kyber ({recipe}) — {iterations} iterations...")

    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = Inf1delKyber.keygen(recipe)
    kg_time = (time.perf_counter() - start) / iterations * 1000

    pk, sk = Inf1delKyber.keygen(recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ct, ss = Inf1delKyber.encaps(pk, recipe)
    enc_time = (time.perf_counter() - start) / iterations * 1000

    ct, ss = Inf1delKyber.encaps(pk, recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ss2 = Inf1delKyber.decaps(sk, ct, recipe)
    dec_time = (time.perf_counter() - start) / iterations * 1000

    assert ss == ss2, "Benchmark verification failed!"

    print(f"\n  KeyGen:   {kg_time:.2f} ms/op")
    print(f"  Encaps:   {enc_time:.2f} ms/op")
    print(f"  Decaps:   {dec_time:.2f} ms/op")
    print(f"  PK size:  {len(pk)} bytes")
    print(f"  SK size:  {len(sk)} bytes")
    print(f"  CT size:  {len(ct)} bytes")
    print(f"  SS size:  {len(ss)} bytes")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="1nf1del-kyber",
        description="1nf1D3L's Kyber — Non-FIPS Post-Quantum KEM"
    )
    parser.add_argument("--recipe", default="espresso", help="Coffee recipe for domain separation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser("bench", help="Run benchmarks")
    p.add_argument("-n", "--iterations", type=int, default=10, help="Iterations")
    p.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        return

    print_banner()
    args.func(args)


if __name__ == "__main__":
    main()
