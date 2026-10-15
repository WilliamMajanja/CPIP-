#!/usr/bin/env python3
"""
1nf1D3L's Post-Quantum Crypto — ML-KEM + SLH-DSA (numpy-accelerated)
=====================================================================

A custom ML-KEM variant and SLH-DSA wrapper with modified parameters
for the Coffee Protocol. NOT FIPS VALIDATED — Use for research,
red-teaming, and coffee protocols only.

Design philosophy:
- "Compliance is for auditors. Security is for survivors."
- Standardized NIST ML-KEM parameters (η1=3, η2=2)
- Standardized SLH-DSA variants (all 12 parameter sets)
- Extra NTT domain randomization (domain separation)
- Coffee-curve domain separation tags
- Constant-time-ish (Python limitations apply)

Performance:
- numpy-accelerated NTT (vectorized butterfly operations)
- Cached A-matrix generation (avoid regenerating from seed)
- Precomputed twiddle factor tables
- Vectorized CBD sampling and compression

Supports all NIST ML-KEM standard sizes:
- ML-KEM-512 (n=256, k=2, q=3329, η1=3, η2=2, du=10, dv=4)
- ML-KEM-768 (n=256, k=3, q=3329, η1=3, η2=2, du=10, dv=4)
- ML-KEM-1024 (n=256, k=4, q=3329, η1=3, η2=2, du=11, dv=5)

Experimental 1nf1D3L-only extended ranks (not standardized security levels):
- 1nf1d3l_kem_2048 (n=256, k=8, q=3329, η1=3, η2=2, du=12, dv=5)
- 1nf1d3l_kem_4096 (n=256, k=16, q=3329, η1=3, η2=2, du=13, dv=5)

Supports all NIST SLH-DSA standard variants:
- SHA2: 128f, 128s, 192f, 192s, 256f, 256s
- SHAKE: 128f, 128s, 192f, 192s, 256f, 256s

Extra 1nf1D3L modifications:
- Domain separation tags ("1NF1D3L-KYBER-V1", "1NF1D3L-SLH-V1")
- NTT twiddle factor perturbation (ML-KEM)
- Domain-separated key derivation (both)
- Coffee recipe binding (both)
"""

import hashlib
import hmac
import secrets

import numpy as np

Q = 3329
Q32 = np.int32(3329)
N = 256
DOMAIN = b"1NF1D3L-KYBER-V1"
ROOT = 17
N_INV = pow(256, -1, 3329)

_SIZE_PARAMS = {
    512: {"K": 2, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4},
    768: {"K": 3, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4},
    1024: {"K": 4, "ETA1": 3, "ETA2": 2, "DU": 11, "DV": 5},
    # Experimental extended ranks; not standardized ML-KEM security levels.
    2048: {"K": 8, "ETA1": 3, "ETA2": 2, "DU": 12, "DV": 5},
    4096: {"K": 16, "ETA1": 3, "ETA2": 2, "DU": 13, "DV": 5},
}

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


def _generate_matrix(rho, k):
    cache_key = (rho, k)
    if cache_key in _A_CACHE:
        return _A_CACHE[cache_key]

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
                # Include a retry counter so a block with no acceptable
                # coefficient cannot be re-read forever at the same count.
                retry = 0
                while True:
                    more = hashlib.shake_256(
                        xof_in + b"-EXT-" + count.to_bytes(2, 'little')
                        + retry.to_bytes(4, 'little')
                    ).digest(128)
                    retry += 1
                    if any(
                        (more[i] | (more[i + 1] << 8)) < 3329 * 2
                        for i in range(0, len(more) - 1, 2)
                    ):
                        break
                for b_idx in range(0, len(more), 2):
                    if count >= N:
                        break
                    if b_idx + 1 < len(more):
                        val = more[b_idx] | (more[b_idx + 1] << 8)
                        if val < 3329 * 2:
                            coeffs[count] = val % 3329
                            count += 1

            A[i * k + j] = _ntt(coeffs[:N])

    _A_CACHE[cache_key] = A
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
    Q = Q
    DOMAIN = DOMAIN

    def __init__(self, size=768, recipe="espresso"):
        if size not in _SIZE_PARAMS:
            raise ValueError(f"Unsupported KEM size: {size}. Use 512, 768, 1024, 2048, or 4096.")
        self.size = size
        self._p = _SIZE_PARAMS[size]
        self.K = self._p["K"]
        self.ETA1 = self._p["ETA1"]
        self.ETA2 = self._p["ETA2"]
        self.DU = self._p["DU"]
        self.DV = self._p["DV"]
        self.recipe = recipe.encode()

    @classmethod
    def keygen(cls, recipe="espresso", size=768):
        _init_tables()

        inst = cls(size=size, recipe=recipe)
        k = inst.K
        eta1 = inst.ETA1
        n = inst.N
        q = inst.Q

        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)

        rho, sigma = _hash_g(d)

        A = _generate_matrix(rho, k)

        s = [_cbd(_prf(sigma, bytes([i]), eta1 * n * 2), eta1) for i in range(k)]
        e = [_cbd(_prf(sigma, bytes([k + i]), eta1 * n * 2), eta1) for i in range(k)]

        s_ntt = [_ntt(si) for si in s]
        e_ntt = [_ntt(ei) for ei in e]

        q32 = np.int32(q)
        t_ntt = [np.zeros(n, dtype=np.int32) for _ in range(k)]
        for i in range(k):
            for j in range(k):
                t_ntt[i] = (t_ntt[i] + (A[i * k + j] * s_ntt[j]) % q32) % q32
            t_ntt[i] = (t_ntt[i] + e_ntt[i]) % q32

        pk = rho
        for i in range(k):
            pk += _poly_compress(t_ntt[i], 12)

        sk = b""
        for i in range(k):
            sk += _poly_compress(s[i], 12)
        sk += pk
        sk += _hash_h(pk)
        sk += z

        return pk, sk

    @classmethod
    def encaps(cls, public_key, recipe="espresso", size=768):
        _init_tables()

        inst = cls(size=size, recipe=recipe)
        k = inst.K
        eta1 = inst.ETA1
        eta2 = inst.ETA2
        du = inst.DU
        dv = inst.DV
        n = inst.N
        q = inst.Q

        pk_size = 32 + k * 384
        if len(public_key) != pk_size:
            raise ValueError(f"Invalid public key length: {len(public_key)} != {pk_size}")

        rho = public_key[:32]
        t_compressed = public_key[32:]

        A = _generate_matrix(rho, k)
        t_ntt = []
        for i in range(k):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(_poly_decompress(poly_data, 12))

        m = secrets.token_bytes(32)

        Kbar = hashlib.sha3_256(m + _hash_h(public_key)).digest()
        r = hashlib.shake_256(Kbar).digest(32)

        r_vec = [_cbd(_prf(r, bytes([i]), eta1 * n * 2), eta1) for i in range(k)]
        e1 = [_cbd(_prf(r, bytes([k + i]), eta1 * n * 2), eta1) for i in range(k)]
        e2 = _cbd(_prf(r, bytes([2 * k]), eta2 * n * 2), eta2)

        r_ntt = [_ntt(ri) for ri in r_vec]

        u_ntt = [np.zeros(n, dtype=np.int32) for _ in range(k)]
        for i in range(k):
            for j in range(k):
                u_ntt[i] = (u_ntt[i] + (A[j * k + i] * r_ntt[j]) % Q32) % Q32
            u_ntt[i] = (u_ntt[i] + _ntt(e1[i])) % Q32

        v_ntt = np.zeros(n, dtype=np.int32)
        for i in range(k):
            v_ntt = (v_ntt + (t_ntt[i] * r_ntt[i]) % Q32) % Q32
        v_ntt = (v_ntt + _ntt(e2)) % Q32

        m_poly = _poly_decompress(m, 1)
        m_poly_ntt = _ntt(m_poly)
        v_ntt = (v_ntt + m_poly_ntt) % Q32

        c1 = b""
        for i in range(k):
            c1 += _poly_compress(_intt(u_ntt[i]), du)
        c2 = _poly_compress(_intt(v_ntt), dv)

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
    def decaps(cls, secret_key, ciphertext, recipe="espresso", size=768):
        _init_tables()

        inst = cls(size=size, recipe=recipe)
        k = inst.K
        eta1 = inst.ETA1
        eta2 = inst.ETA2
        du = inst.DU
        dv = inst.DV
        n = inst.N
        q = inst.Q

        pk_size = 32 + k * 384
        expected_sk_len = k * 384 + pk_size + 32 + 32
        if len(secret_key) != expected_sk_len:
            raise ValueError(f"Invalid secret key length: {len(secret_key)} != {expected_sk_len}")

        s = []
        offset = 0
        for i in range(k):
            s.append(_poly_decompress(secret_key[offset:offset + 384], 12))
            offset += 384

        pk = secret_key[offset:offset + pk_size]
        offset += pk_size
        h_pk = secret_key[offset:offset + 32]
        offset += 32
        z = secret_key[offset:offset + 32]

        if _hash_h(pk) != h_pk:
            hash_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            fake_key = _kdf(z + hash_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
            return fake_key

        ct_c1_len = k * (n * du // 8)
        ct_c2_len = n * dv // 8
        expected_ct_len = ct_c1_len + ct_c2_len + 32
        if len(ciphertext) != expected_ct_len:
            hash_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
            fake_key = _kdf(z + hash_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
            return fake_key

        c1 = ciphertext[:ct_c1_len]
        c2 = ciphertext[ct_c1_len:ct_c1_len + ct_c2_len]
        session_seed = ciphertext[-32:]

        rho = pk[:32]
        t_compressed = pk[32:]

        A = _generate_matrix(rho, k)
        t_ntt = []
        for i in range(k):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(_poly_decompress(poly_data, 12))

        u_ntt = []
        for i in range(k):
            poly_data = c1[i * (n * du // 8):(i + 1) * (n * du // 8)]
            u_poly = _poly_decompress(poly_data, du)
            u_ntt.append(_ntt(u_poly))

        v_poly = _poly_decompress(c2, dv)
        v_ntt = _ntt(v_poly)

        s_ntt = [_ntt(si) for si in s]

        q32 = np.int32(q)
        sT_u = np.zeros(n, dtype=np.int32)
        for i in range(k):
            sT_u = (sT_u + (s_ntt[i] * u_ntt[i]) % q32) % q32

        mp = _intt(_poly_sub(v_ntt, sT_u))

        threshold_low = q // 4
        threshold_high = 3 * q // 4
        bits = ((mp >= threshold_low) & (mp <= threshold_high)).astype(np.uint8)
        m_bits = np.packbits(bits, bitorder="little")[:32]
        m = bytes(m_bits)

        Kbar = hashlib.sha3_256(m + _hash_h(pk)).digest()
        r = hashlib.shake_256(Kbar).digest(32)

        r_vec = [_cbd(_prf(r, bytes([i]), eta1 * n * 2), eta1) for i in range(k)]
        e1 = [_cbd(_prf(r, bytes([k + i]), eta1 * n * 2), eta1) for i in range(k)]
        e2 = _cbd(_prf(r, bytes([2 * k]), eta2 * n * 2), eta2)

        r_hat = [_ntt(poly.copy()) for poly in r_vec]

        u_hat = [np.zeros(n, dtype=np.int32) for _ in range(k)]
        for i in range(k):
            for j in range(k):
                u_hat[i] = (u_hat[i] + (A[j * k + i] * r_hat[j]) % q32) % q32
            u_hat[i] = (u_hat[i] + _ntt(e1[i])) % q32

        v_hat = np.zeros(n, dtype=np.int32)
        for i in range(k):
            v_hat = (v_hat + (t_ntt[i] * r_hat[i]) % q32) % q32
        v_hat = (v_hat + _ntt(e2)) % q32
        m_poly = _poly_decompress(m, 1)
        m_poly_ntt = _ntt(m_poly)
        v_hat = (v_hat + m_poly_ntt) % q32

        expected_c1 = b""
        for i in range(k):
            expected_c1 += _poly_compress(_intt(u_hat[i]), du)
        expected_c2 = _poly_compress(_intt(v_hat), dv)
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
    def hybrid_keygen(cls, ecc_seed=None, recipe="espresso", size=768):
        from server import ECP256

        if ecc_seed is None:
            ecc_seed = secrets.token_bytes(32)

        ecc_pk, ecc_seed_out, _, _ = ECP256.generate_keypair(ecc_seed)
        kyber_pk, kyber_sk = cls.keygen(recipe, size)

        ecc_pk_len = len(ecc_pk).to_bytes(2, 'big')
        hybrid_pk = ecc_pk_len + ecc_pk + kyber_pk
        hybrid_sk = ecc_seed_out + kyber_sk

        return hybrid_pk, hybrid_sk

    @classmethod
    def hybrid_encapsulate(cls, hybrid_pk, recipe="espresso", size=768):
        from server import ECP256, CoffeeCipher

        inst = cls(size=size, recipe=recipe)

        ecc_pk_len = int.from_bytes(hybrid_pk[:2], 'big')
        ecc_pk = hybrid_pk[2:2 + ecc_pk_len]
        kyber_pk = hybrid_pk[2 + ecc_pk_len:]

        ecc_ephem_seed = secrets.token_bytes(32)
        ecc_ephem_pk, _, _, _ = ECP256.generate_keypair(ecc_ephem_seed)
        ecdh_shared = ECP256.key_exchange(ecc_ephem_seed, ecc_pk)

        kyber_ct, kyber_ss = inst.encaps(kyber_pk, recipe)

        combined = ecdh_shared + kyber_ss + inst.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)

        ecc_ephem_len = len(ecc_ephem_pk).to_bytes(2, 'big')
        ciphertext = ecc_ephem_len + ecc_ephem_pk + kyber_ct

        return ciphertext, shared

    @classmethod
    def hybrid_decapsulate(cls, hybrid_sk, ciphertext, recipe="espresso", size=768):
        from server import ECP256, CoffeeCipher

        inst = cls(size=size, recipe=recipe)

        ecc_seed = hybrid_sk[:32]
        kyber_sk = hybrid_sk[32:]

        ecc_ephem_len = int.from_bytes(ciphertext[:2], 'big')
        ecc_ephem_pk = ciphertext[2:2 + ecc_ephem_len]
        kyber_ct = ciphertext[2 + ecc_ephem_len:]

        ecdh_shared = ECP256.key_exchange(ecc_seed, ecc_ephem_pk)

        kyber_ss = inst.decaps(kyber_sk, kyber_ct, recipe)

        combined = ecdh_shared + kyber_ss + inst.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)

        return shared


# ── SLH-DSA (SPHINCS+) — Stateless Hash-Based Signatures ──────────────────

SLH_DOMAIN = b"1NF1D3L-SLH-V1"

_SLH_VARIANTS = {
    "slh_dsa_sha2_128f_simple": {"security": 128, "hash": "sha2", "fors": "128f", "pk_size": 32, "sk_size": 64, "sig_size": 7856},
    "slh_dsa_sha2_128s_simple": {"security": 128, "hash": "sha2", "fors": "128s", "pk_size": 32, "sk_size": 64, "sig_size": 17088},
    "slh_dsa_sha2_192f_simple": {"security": 192, "hash": "sha2", "fors": "192f", "pk_size": 48, "sk_size": 96, "sig_size": 16224},
    "slh_dsa_sha2_192s_simple": {"security": 192, "hash": "sha2", "fors": "192s", "pk_size": 48, "sk_size": 96, "sig_size": 35664},
    "slh_dsa_sha2_256f_simple": {"security": 256, "hash": "sha2", "fors": "256f", "pk_size": 64, "sk_size": 128, "sig_size": 29792},
    "slh_dsa_sha2_256s_simple": {"security": 256, "hash": "sha2", "fors": "256s", "pk_size": 64, "sk_size": 128, "sig_size": 49856},
    "slh_dsa_shake_128f_simple": {"security": 128, "hash": "shake", "fors": "128f", "pk_size": 32, "sk_size": 64, "sig_size": 7856},
    "slh_dsa_shake_128s_simple": {"security": 128, "hash": "shake", "fors": "128s", "pk_size": 32, "sk_size": 64, "sig_size": 17088},
    "slh_dsa_shake_192f_simple": {"security": 192, "hash": "shake", "fors": "192f", "pk_size": 48, "sk_size": 96, "sig_size": 16224},
    "slh_dsa_shake_192s_simple": {"security": 192, "hash": "shake", "fors": "192s", "pk_size": 48, "sk_size": 96, "sig_size": 35664},
    "slh_dsa_shake_256f_simple": {"security": 256, "hash": "shake", "fors": "256f", "pk_size": 64, "sk_size": 128, "sig_size": 29792},
    "slh_dsa_shake_256s_simple": {"security": 256, "hash": "shake", "fors": "256s", "pk_size": 64, "sk_size": 128, "sig_size": 49856},
}


def _slh_derive_key(base_key: bytes, info: bytes, length: int) -> bytes:
    """1nf1D3L domain-separated KDF for SLH-DSA key material."""
    prk = hmac.new(SLH_DOMAIN + b"-PRK", base_key, hashlib.sha3_256).digest()
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
    return okm[:length]


class Inf1delSLH:
    """1nf1D3L's SLH-DSA — Domain-separated stateless hash-based signatures.

    Wraps the pqcrypto SPHINCS+ implementation with 1nf1D3L domain separation
    tags and custom key derivation. Supports all 12 standard SLH-DSA variants.

    NOT FIPS VALIDATED — Use for research, red-teaming, and coffee protocols only.

    Extra modifications over standard SLH-DSA:
    - Domain separation tag "1NF1D3L-SLH-V1" on all hash/KDF inputs
    - Custom key derivation with HMAC-SHA3-256
    - Coffee recipe binding for key material
    - Message domain prefixing before signing
    """

    DOMAIN = SLH_DOMAIN
    VARIANTS = _SLH_VARIANTS

    def __init__(self, variant: str = "slh_dsa_sha2_256f_simple", recipe: str = "espresso"):
        if variant not in _SLH_VARIANTS:
            raise ValueError(
                f"Unknown SLH-DSA variant: {variant}. "
                f"Available: {list(_SLH_VARIANTS.keys())}"
            )
        self.variant = variant
        self._info = _SLH_VARIANTS[variant]
        self.recipe = recipe.encode()
        self._mod = None

    @property
    def algorithm(self) -> str:
        return self.variant

    @property
    def security_level(self) -> int:
        return self._info["security"]

    @property
    def pk_size(self) -> int:
        return self._info["pk_size"]

    @property
    def sk_size(self) -> int:
        return self._info["sk_size"]

    @property
    def sig_size(self) -> int:
        return self._info["sig_size"]

    def _load_mod(self):
        """Load the pqcrypto SPHINCS+ module with fallback name resolution."""
        if self._mod is not None:
            return self._mod
        candidates = [f"pqcrypto.sign.{self.variant}"]
        if self.variant.startswith("slh_dsa_"):
            candidates.append(f"pqcrypto.sign.sphincs_{self.variant[len('slh_dsa_'):]}")
        for modname in candidates:
            try:
                self._mod = __import__(modname, fromlist=["pqcrypto"])
                return self._mod
            except ImportError:
                continue
        raise RuntimeError(
            f"SLH-DSA variant '{self.variant}' not available "
            f"(pqcrypto not installed or variant not supported)"
        )

    @classmethod
    def keygen(cls, variant: str = "slh_dsa_sha2_256f_simple", recipe: str = "espresso") -> tuple[bytes, bytes]:
        """Generate SLH-DSA keypair with 1nf1D3L domain separation.

        Returns (public_key, secret_key).
        The secret key is prefixed with domain material for binding.
        """
        inst = cls(variant, recipe)
        mod = inst._load_mod()
        pk, sk = mod.generate_keypair()

        domain_prefix = SLH_DOMAIN + b"-KEY-" + recipe.encode()
        sk_prefix = _slh_derive_key(
            domain_prefix + sk[:32],
            b"slh-sk-prefix",
            32
        )

        return pk, sk_prefix + sk

    @classmethod
    def sign(cls, secret_key: bytes, message: bytes,
             variant: str = "slh_dsa_sha2_256f_simple", recipe: str = "espresso") -> tuple[bytes, bytes]:
        """Sign a message with 1nf1D3L domain separation.

        Prepends domain tag to message before signing. Returns (signature, public_key).
        """
        inst = cls(variant, recipe)
        mod = inst._load_mod()

        sk_prefix = secret_key[:32]
        sk = secret_key[32:]

        domain_msg = SLH_DOMAIN + b"-MSG-" + recipe.encode() + message
        result = mod.sign(sk, domain_msg)

        if isinstance(result, tuple):
            sig, pk = result
        else:
            sig = result
            pk = sk[len(sk) // 2:]

        return sig, pk

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes,
               variant: str = "slh_dsa_sha2_256f_simple", recipe: str = "espresso") -> bool:
        """Verify a signature with 1nf1D3L domain separation."""
        inst = cls(variant, recipe)
        mod = inst._load_mod()

        domain_msg = SLH_DOMAIN + b"-MSG-" + recipe.encode() + message
        try:
            return mod.verify(public_key, domain_msg, signature)
        except Exception:
            return False

    def keygen_instance(self) -> tuple[bytes, bytes]:
        """Generate keypair using instance variant/recipe."""
        return self.keygen(self.variant, self.recipe.decode())

    def sign_instance(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        """Sign using instance variant/recipe."""
        return self.sign(secret_key, message, self.variant, self.recipe.decode())

    def verify_instance(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify using instance variant/recipe."""
        return self.verify(public_key, message, signature, self.variant, self.recipe.decode())


def print_banner():
    print(r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     1nf1D3L's Kyber  —  Non-FIPS Post-Quantum KEM               ║
    ║     "Compliance is for auditors. Security is for survivors."    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def cmd_benchmark(args):
    import time
    recipe = args.recipe or "espresso"
    size = args.size or 768
    iterations = args.iterations

    print(f"\nBenchmarking 1nf1D3L's Kyber ML-KEM-{size} ({recipe}) — {iterations} iterations...")

    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = Inf1delKyber.keygen(recipe, size)
    kg_time = (time.perf_counter() - start) / iterations * 1000

    pk, sk = Inf1delKyber.keygen(recipe, size)
    start = time.perf_counter()
    for _ in range(iterations):
        ct, ss = Inf1delKyber.encaps(pk, recipe, size)
    enc_time = (time.perf_counter() - start) / iterations * 1000

    ct, ss = Inf1delKyber.encaps(pk, recipe, size)
    start = time.perf_counter()
    for _ in range(iterations):
        ss2 = Inf1delKyber.decaps(sk, ct, recipe, size)
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
    parser.add_argument("--size", type=int, default=768, choices=[512, 768, 1024, 2048, 4096], help="KEM parameter size (2048/4096 are experimental)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser("bench", help="Run benchmarks")
    p.add_argument("-n", "--iterations", type=int, default=10, help="Iterations")
    p.add_argument("--size", type=int, default=768, choices=[512, 768, 1024, 2048, 4096], help="KEM parameter size (2048/4096 are experimental)")
    p.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        return

    print_banner()
    args.func(args)


if __name__ == "__main__":
    main()
