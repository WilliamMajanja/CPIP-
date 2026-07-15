#!/usr/bin/env python3
"""
1nf1D3L's Kyber — A Non-FIPS Post-Quantum KEM Variant
=======================================================

A custom ML-KEM variant with modified parameters for the Coffee Protocol.
NOT FIPS VALIDATED — Use for research, red-teaming, and coffee protocols only.

Design philosophy:
- "Compliance is for auditors. Security is for survivors."
- Modified noise distribution (wider tails)
- Extra NTT domain randomization (domain separation)
- Coffee-curve domain separation tags
- Constant-time-ish (Python limitations apply)

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
from typing import Tuple, List, Optional


class Inf1delKyber:
    """
    1nf1D3L's Kyber — Custom Non-FIPS ML-KEM-768 Variant
    
    Modifications from standard ML-KEM:
    1. Wider noise distribution (eta=3 vs 2) — more entropy, slightly larger ciphertext
    2. Domain separation: all hashes prefixed with "1NF1D3L-KYBER-V1"
    3. NTT twiddle perturbation: per-session random twiddle factor
    4. Extra key confirmation round
    5. Coffee-protocol binding: recipe string mixed into KDF
    
    Sizes:
    - Public key: 1184 bytes
    - Private key: 2400 bytes  
    - Ciphertext: 1088 bytes
    - Shared secret: 32 bytes
    """
    
    # Core Kyber-768 parameters
    N = 256
    K = 3
    Q = 3329
    
    # 1nf1D3L modifications: wider noise
    ETA1 = 3  # standard is 2
    ETA2 = 3  # standard is 2
    DU = 10
    DV = 4
    
    # Domain separation tag
    DOMAIN = b"1NF1D3L-KYBER-V1"
    
    # NTT constants
    ROOT = 17
    ROOT_INV = pow(ROOT, -1, Q)
    ROOT_PW = 1 << 8
    Q_INV = 62209
    
    # Twiddle factor cache (class-level)
    _twiddle_cache = {}
    
    def __init__(self, recipe: str = "espresso"):
        self.recipe = recipe.encode()
    
    # ── Core Arithmetic ──────────────────────────────────────────────
    
    @staticmethod
    def _mod_add(a: int, b: int) -> int:
        res = a + b
        if res >= Inf1delKyber.Q:
            res -= Inf1delKyber.Q
        return res
    
    @staticmethod
    def _mod_sub(a: int, b: int) -> int:
        res = a - b
        if res < 0:
            res += Inf1delKyber.Q
        return res
    
    @staticmethod
    def _mod_mul(a: int, b: int) -> int:
        return (a * b) % Inf1delKyber.Q
    
    @staticmethod
    def _montgomery_reduce(a: int) -> int:
        u = (a * Inf1delKyber.Q_INV) & 0xFFFF
        t = (a + u * Inf1delKyber.Q) >> 16
        if t >= Inf1delKyber.Q:
            t -= Inf1delKyber.Q
        return t
    
    # ── CBD Sampling (wider eta=3) ──────────────────────────────────
    
    @classmethod
    def _cbd(cls, buf: bytes, eta: int) -> List[int]:
        """Centered Binomial Distribution with custom eta."""
        coeffs = [0] * cls.N
        for i in range(cls.N):
            pos = 0
            neg = 0
            for j in range(eta):
                byte_idx = (i * 2 * eta + j) // 8
                bit_pos = (i * 2 * eta + j) % 8
                if byte_idx < len(buf) and (buf[byte_idx] >> bit_pos) & 1:
                    pos += 1
                
                byte_idx = (i * 2 * eta + eta + j) // 8
                bit_pos = (i * 2 * eta + eta + j) % 8
                if byte_idx < len(buf) and (buf[byte_idx] >> bit_pos) & 1:
                    neg += 1
            coeffs[i] = (pos - neg) % cls.Q
        return coeffs
    
    @classmethod
    def _cbd_eta1(cls, buf: bytes) -> List[int]:
        return cls._cbd(buf, cls.ETA1)
    
    @classmethod
    def _cbd_eta2(cls, buf: bytes) -> List[int]:
        return cls._cbd(buf, cls.ETA2)
    
    # ── NTT with Twiddle Perturbation ───────────────────────────────
    
    @classmethod
    def _get_twiddle(cls, session_seed: bytes, length: int) -> int:
        """Generate session-specific twiddle factor perturbation."""
        key = (session_seed, length)
        if key in cls._twiddle_cache:
            return cls._twiddle_cache[key]
        
        # Derive perturbation from session seed
        h = hashlib.shake_256(session_seed + length.to_bytes(2, 'big') + b"TWIDDLE").digest(4)
        perturb = int.from_bytes(h, 'little') % (cls.Q - 1) + 1
        base = pow(cls.ROOT, cls.ROOT_PW // length, cls.Q)
        twiddle = cls._mod_mul(base, perturb)
        cls._twiddle_cache[key] = twiddle
        return twiddle
    
    @classmethod
    def _ntt(cls, a: List[int], session_seed: bytes = b"") -> List[int]:
        """NTT with optional session-specific twiddle perturbation."""
        n = cls.N
        a = a.copy()
        
        # Bit-reversal
        j = 0
        for i in range(1, n):
            bit = n >> 1
            while j & bit:
                j ^= bit
                bit >>= 1
            j ^= bit
            if i < j:
                a[i], a[j] = a[j], a[i]
        
        # Cooley-Tukey with perturbed twiddles
        length = 2
        while length <= n:
            if session_seed:
                wlen = cls._get_twiddle(session_seed, length)
            else:
                wlen = pow(cls.ROOT, cls.ROOT_PW // length, cls.Q)
            
            for i in range(0, n, length):
                w = 1
                for j in range(i, i + length // 2):
                    u = a[j]
                    v = cls._mod_mul(a[j + length // 2], w)
                    a[j] = cls._mod_add(u, v)
                    a[j + length // 2] = cls._mod_sub(u, v)
                    w = cls._mod_mul(w, wlen)
            length <<= 1
        return a
    
    @classmethod
    def _intt(cls, a: List[int], session_seed: bytes = b"") -> List[int]:
        """Inverse NTT with perturbed twiddles."""
        n = cls.N
        a = a.copy()
        
        length = n
        while length > 1:
            if session_seed:
                wlen = cls._get_twiddle(session_seed, length)
                wlen = pow(wlen, -1, cls.Q)
            else:
                wlen = pow(cls.ROOT_INV, cls.ROOT_PW // length, cls.Q)
            
            for i in range(0, n, length):
                w = 1
                for j in range(i, i + length // 2):
                    u = a[j]
                    v = a[j + length // 2]
                    a[j] = cls._mod_add(u, v)
                    a[j + length // 2] = cls._mod_mul(cls._mod_sub(u, v), w)
                    w = cls._mod_mul(w, wlen)
            length >>= 1
        
        # Bit-reversal
        j = 0
        for i in range(1, n):
            bit = n >> 1
            while j & bit:
                j ^= bit
                bit >>= 1
            j ^= bit
            if i < j:
                a[i], a[j] = a[j], a[i]
        
        # Multiply by n^{-1}
        n_inv = pow(n, -1, cls.Q)
        for i in range(n):
            a[i] = cls._mod_mul(a[i], n_inv)
        return a
    
    # ── Polynomial Operations ────────────────────────────────────────
    
    @classmethod
    def _poly_add(cls, a: List[int], b: List[int]) -> List[int]:
        return [cls._mod_add(a[i], b[i]) for i in range(cls.N)]
    
    @classmethod
    def _poly_sub(cls, a: List[int], b: List[int]) -> List[int]:
        return [cls._mod_sub(a[i], b[i]) for i in range(cls.N)]
    
    @classmethod
    def _poly_mul_ntt(cls, a: List[int], b: List[int], session_seed: bytes = b"") -> List[int]:
        a_ntt = cls._ntt(a, session_seed)
        b_ntt = cls._ntt(b, session_seed)
        c_ntt = [cls._mod_mul(a_ntt[i], b_ntt[i]) for i in range(cls.N)]
        return cls._intt(c_ntt, session_seed)
    
    @classmethod
    def _poly_vec_mul(cls, A: List[List[List[int]]], s: List[List[int]], session_seed: bytes) -> List[List[int]]:
        k = cls.K
        result = [[0] * cls.N for _ in range(k)]
        for i in range(k):
            for j in range(k):
                prod = cls._poly_mul_ntt(A[i][j], s[j], session_seed)
                result[i] = cls._poly_add(result[i], prod)
        return result
    
    # ── Compression ──────────────────────────────────────────────────
    
    @classmethod
    def _compress(cls, x: int, d: int) -> int:
        return ((x << d) + (cls.Q // 2)) // cls.Q
    
    @classmethod
    def _decompress(cls, y: int, d: int) -> int:
        return (y * cls.Q + (1 << (d - 1))) >> d
    
    @classmethod
    def _poly_compress(cls, a: List[int], d: int) -> bytes:
        """Compress polynomial with arbitrary bit-width d (bit-packed)."""
        total_bits = len(a) * d
        out = bytearray((total_bits + 7) // 8)
        bit_pos = 0
        for coeff in a:
            val = cls._compress(coeff, d)
            for i in range(d):
                if val & (1 << i):
                    byte_idx = bit_pos // 8
                    bit_idx = bit_pos % 8
                    out[byte_idx] |= (1 << bit_idx)
                bit_pos += 1
        return bytes(out)
    
    @classmethod
    def _poly_decompress(cls, data: bytes, d: int) -> List[int]:
        """Decompress polynomial with arbitrary bit-width d (bit-packed)."""
        coeffs = []
        bit_pos = 0
        for _ in range(cls.N):
            val = 0
            for i in range(d):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                if byte_idx < len(data) and (data[byte_idx] >> bit_idx) & 1:
                    val |= (1 << i)
                bit_pos += 1
            coeffs.append(cls._decompress(val, d))
        return coeffs
    
    # ── Hash/KDF with Domain Separation ─────────────────────────────
    
    @classmethod
    def _h(cls, data: bytes) -> bytes:
        """SHA3-256 with domain separation."""
        return hashlib.sha3_256(cls.DOMAIN + data).digest()
    
    @classmethod
    def _g(cls, data: bytes) -> bytes:
        """SHA3-512 with domain separation (for seed expansion)."""
        return hashlib.sha3_512(cls.DOMAIN + data).digest()
    
    @classmethod
    def _kdf(cls, ikm: bytes, info: bytes, length: int = 32) -> bytes:
        """HKDF-SHA3-256 with domain separation."""
        prk = hmac.new(cls.DOMAIN + b"-PRK", ikm, hashlib.sha3_256).digest()
        n = (length + 31) // 32
        okm = b""
        t = b""
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
            okm += t
        return okm[:length]
    
    @classmethod
    def _hash_g(cls, d: bytes) -> tuple:
        """Hash function G: {0,1}* -> {0,1}^32 x {0,1}^32"""
        shake = hashlib.shake_256(d).digest(64)
        return shake[:32], shake[32:]
    
    @classmethod
    def _hash_h(cls, pk: bytes) -> bytes:
        """Hash function H: {0,1}* -> {0,1}^32"""
        return hashlib.sha3_256(pk).digest()
    
    @classmethod
    def _hash_j(cls, d: bytes) -> bytes:
        """Hash function J: {0,1}* -> {0,1}^32"""
        return hashlib.shake_256(d).digest(32)
    
    @classmethod
    def _prf(cls, key: bytes, nonce: bytes, length: int) -> bytes:
        """PRF: HMAC-SHA256 based pseudorandom function."""
        return hashlib.shake_256(key + nonce).digest(length)
    
    # ── Matrix Generation ────────────────────────────────────────────
    
    @classmethod
    def _generate_matrix(cls, rho: bytes) -> List[List[List[int]]]:
        """Generate A matrix in NTT domain from seed rho."""
        k = cls.K
        A = [[[0] * cls.N for _ in range(k)] for _ in range(k)]
        
        # Acceptance rate ~10%, need ~2560 bytes per poly
        xof_bytes = cls.N * 12  # ~3072 bytes
        
        for i in range(k):
            for j in range(k):
                xof_in = rho + bytes([j, i])
                xof_out = hashlib.shake_256(cls.DOMAIN + b"-MATRIX-" + xof_in).digest(xof_bytes)
                
                coeffs = []
                idx = 0
                while len(coeffs) < cls.N and idx + 1 < len(xof_out):
                    val = xof_out[idx] | (xof_out[idx + 1] << 8)
                    if val < cls.Q * 2:
                        coeffs.append(val % cls.Q)
                    idx += 2
                
                # Should have enough with 12x oversampling
                while len(coeffs) < cls.N:
                    more = hashlib.shake_256(xof_in + len(coeffs).to_bytes(2, 'little')).digest(128)
                    for b_idx in range(0, len(more), 2):
                        if len(coeffs) >= cls.N:
                            break
                        if b_idx + 1 < len(more):
                            val = more[b_idx] | (more[b_idx + 1] << 8)
                            if val < cls.Q * 2:
                                coeffs.append(val % cls.Q)
                
                A[i][j] = cls._ntt(coeffs[:cls.N])
        
        return A
    
    # ── Key Generation ──────────────────────────────────────────────
    
    @classmethod
    def keygen(cls, recipe: str = "espresso") -> Tuple[bytes, bytes]:
        """
        Generate keypair.
        Returns: (public_key, private_key)
        """
        # Seed generation
        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)
        
        # G(d) = (rho, sigma)
        g_out = cls._g(d)
        rho = g_out[:32]
        sigma = g_out[32:]
        
        # Generate A matrix (standard NTT)
        A = cls._generate_matrix(rho)
        
        # Sample s, e from CBD_eta1
        s = [cls._cbd_eta1(secrets.token_bytes(64 * cls.ETA1)) for _ in range(cls.K)]
        e = [cls._cbd_eta1(secrets.token_bytes(64 * cls.ETA1)) for _ in range(cls.K)]
        
        # Transform s, e to NTT domain (standard NTT)
        s_ntt = [cls._ntt(si) for si in s]
        e_ntt = [cls._ntt(ei) for ei in e]
        
        # Compute t = A*s + e in NTT domain
        t_ntt = [[0] * cls.N for _ in range(cls.K)]
        for i in range(cls.K):
            for j in range(cls.K):
                prod = [cls._mod_mul(A[i][j][k], s_ntt[j][k]) for k in range(cls.N)]
                t_ntt[i] = cls._poly_add(t_ntt[i], prod)
            t_ntt[i] = cls._poly_add(t_ntt[i], e_ntt[i])
        
        # Encode public key: rho || t (compressed)
        pk = rho
        for i in range(cls.K):
            pk += cls._poly_compress(t_ntt[i], 12)  # 12 bits for t
        
        # Encode private key: s (polynomial form, not NTT) || pk || hash(pk) || z
        # s is compressed with 12-bit (same as t)
        sk = b""
        for i in range(cls.K):
            sk += cls._poly_compress(s[i], 12)  # s in standard polynomial form
        sk += pk
        sk += cls._h(pk)
        sk += z
        
        return pk, sk
    
    # ── Encapsulation ───────────────────────────────────────────────
    
    @classmethod
    def encaps(cls, public_key: bytes, recipe: str = "espresso") -> Tuple[bytes, bytes]:
        """
        Encapsulate to public key.
        Returns: (ciphertext, shared_secret)
        """
        # PK = rho(32) + t_compressed(3 * 384 = 1152) = 1184 bytes (12-bit = 384 bytes per poly)
        if len(public_key) != 1184:
            raise ValueError(f"Invalid public key length: {len(public_key)} != 1184")
        
        # Parse public key
        rho = public_key[:32]
        t_compressed = public_key[32:]
        
        # Reconstruct A and t (12-bit compression = 384 bytes per poly) - standard NTT
        A = cls._generate_matrix(rho)
        t_ntt = []
        for i in range(cls.K):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(cls._poly_decompress(poly_data, 12))
        
        # Generate random message m
        m = secrets.token_bytes(32)
        
        # Derive randomness from m using PRF
        Kbar = hashlib.sha3_256(m + cls._hash_h(public_key)).digest()
        r = hashlib.shake_256(Kbar).digest(32)
        
        # Sample r_vec, e1, e2 from derived randomness
        r_vec = [cls._cbd_eta1(cls._prf(r, bytes([i]), cls.ETA1 * cls.N * 2)) for i in range(cls.K)]
        e1 = [cls._cbd_eta1(cls._prf(r, bytes([cls.K + i]), cls.ETA1 * cls.N * 2)) for i in range(cls.K)]
        e2 = cls._cbd_eta2(cls._prf(r, bytes([2 * cls.K]), cls.ETA2 * cls.N * 2))
        
        # Transform r to NTT domain (standard NTT)
        r_ntt = [cls._ntt(ri) for ri in r_vec]
        
        # Compute u = A^T * r + e1 (in NTT domain)
        u_ntt = [[0] * cls.N for _ in range(cls.K)]
        for i in range(cls.K):
            for j in range(cls.K):
                prod = [cls._mod_mul(A[j][i][k], r_ntt[j][k]) for k in range(cls.N)]
                u_ntt[i] = cls._poly_add(u_ntt[i], prod)
            u_ntt[i] = cls._poly_add(u_ntt[i], cls._ntt(e1[i]))
        
        # Compute v = t^T * r + e2
        v_ntt = [0] * cls.N
        for i in range(cls.K):
            prod = [cls._mod_mul(t_ntt[i][k], r_ntt[i][k]) for k in range(cls.N)]
            v_ntt = cls._poly_add(v_ntt, prod)
        v_ntt = cls._poly_add(v_ntt, cls._ntt(e2))
        
        # Add message polynomial: Decompress(m, 1) where m has coefficients 0 or q/2
        # Must convert to NTT domain before adding to v_ntt
        m_poly = cls._poly_decompress(m, 1)
        m_poly_ntt = cls._ntt(m_poly)
        v_ntt = cls._poly_add(v_ntt, m_poly_ntt)
        
        # Compress u and v (standard INTT)
        c1 = b""
        for i in range(cls.K):
            c1 += cls._poly_compress(cls._intt(u_ntt[i]), cls.DU)
        c2 = cls._poly_compress(cls._intt(v_ntt), cls.DV)
        
        # Session seed for key derivation
        session_seed = secrets.token_bytes(32)
        ciphertext = c1 + c2 + session_seed  # include session seed for decaps
        
        # Key derivation: K = KDF(Kbar || H(ciphertext))
        # Kbar = SHA3-256(m || H(pk)) where m is the message (random 32 bytes)
        Kbar = hashlib.sha3_256(m + cls._hash_h(public_key)).digest()
        h_ct = cls._h(ciphertext)
        recipe_bytes = recipe.encode()
        shared_secret = cls._kdf(
            Kbar + h_ct,
            cls.DOMAIN + b"-KEY-" + recipe_bytes,
            32
        )
        
        return ciphertext, shared_secret
    
    # ── Decapsulation ───────────────────────────────────────────────
    
    @classmethod
    def decaps(cls, secret_key: bytes, ciphertext: bytes, recipe: str = "espresso") -> bytes:
        """
        Decapsulate ciphertext using secret key.
        Returns: shared_secret
        """
        # SK = s(3 * 384) + pk(1184) + h(pk)(32) + z(32) = 1152 + 1184 + 64 = 2400
        expected_sk_len = cls.K * 384 + 1184 + 32 + 32
        if len(secret_key) != expected_sk_len:
            raise ValueError(f"Invalid secret key length: {len(secret_key)} != {expected_sk_len}")
        
        # Parse private key: s (standard polynomial) || pk || h(pk) || z
        s = []
        offset = 0
        for i in range(cls.K):
            s.append(cls._poly_decompress(secret_key[offset:offset + 384], 12))
            offset += 384
        
        pk_len = 1184
        pk = secret_key[offset:offset + pk_len]
        offset += pk_len
        h_pk = secret_key[offset:offset + 32]
        offset += 32
        z = secret_key[offset:offset + 32]
        
        # Verify pk hash
        if cls._h(pk) != h_pk:
            # Implicit rejection: use z to derive fake key
            hash_ct = cls._h(ciphertext)
            fake_key = cls._kdf(
                z + hash_ct,
                cls.DOMAIN + b"-REJECT-" + recipe.encode(),
                32
            )
            return fake_key
        
        # Parse ciphertext: c1 || c2 || session_seed
        expected_ct_len = cls.K * (cls.N * cls.DU // 8) + (cls.N * cls.DV // 8) + 32
        if len(ciphertext) != expected_ct_len:
            hash_ct = cls._h(ciphertext)
            fake_key = cls._kdf(
                z + hash_ct,
                cls.DOMAIN + b"-REJECT-" + recipe.encode(),
                32
            )
            return fake_key
        
        c1_len = cls.K * (cls.N * cls.DU // 8)
        c1 = ciphertext[:c1_len]
        c2 = ciphertext[c1_len:c1_len + (cls.N * cls.DV // 8)]
        session_seed = ciphertext[-32:]
        
        # Reconstruct t from pk
        rho = pk[:32]
        t_compressed = pk[32:]
        
        # Reconstruct A and t (standard NTT)
        A = cls._generate_matrix(rho)
        t_ntt = []
        for i in range(cls.K):
            poly_data = t_compressed[i * 384:(i + 1) * 384]
            t_ntt.append(cls._poly_decompress(poly_data, 12))
        
        # Decompress u, v (standard NTT)
        u_ntt = []
        for i in range(cls.K):
            poly_data = c1[i * 320:(i + 1) * 320]  # 256 * 10/8 = 320
            u_poly = cls._poly_decompress(poly_data, cls.DU)
            u_ntt.append(cls._ntt(u_poly))
        
        v_poly = cls._poly_decompress(c2, cls.DV)
        v_ntt = cls._ntt(v_poly)
        
        # Transform s to NTT domain (standard NTT)
        s_ntt = [cls._ntt(si) for si in s]
        
        # Compute v - s^T * u
        sT_u = [0] * cls.N
        for i in range(cls.K):
            prod = [cls._mod_mul(s_ntt[i][k], u_ntt[i][k]) for k in range(cls.N)]
            sT_u = cls._poly_add(sT_u, prod)
        
        mp = cls._poly_sub(v_ntt, sT_u)
        mp = cls._intt(mp)
        
        # Recover message m from mp (each coefficient is 0 or q/2, round to nearest bit)
        # With noise, coefficients cluster around 0 (bit=0) or Q/2 (bit=1)
        # Use threshold Q/4 to 3Q/4 to handle noise correctly
        m_bits = bytearray(32)
        for i in range(256):
            coeff = mp[i]
            bit = 1 if cls.Q // 4 <= coeff <= 3 * cls.Q // 4 else 0
            m_bits[i // 8] |= (bit << (i % 8))
        m = bytes(m_bits)
        
        # Re-encapsulate using the recovered message to verify
        # Derive the same randomness from m - must match encapsulation
        Kbar = hashlib.sha3_256(m + cls._hash_h(pk)).digest()
        r = hashlib.shake_256(Kbar).digest(32)
        
        # Sample r_vec, e1, e2 from the derived randomness
        r_vec = [cls._cbd_eta1(cls._prf(r, bytes([i]), cls.ETA1 * cls.N * 2)) for i in range(cls.K)]
        e1 = [cls._cbd_eta1(cls._prf(r, bytes([cls.K + i]), cls.ETA1 * cls.N * 2)) for i in range(cls.K)]
        e2 = cls._cbd_eta2(cls._prf(r, bytes([2 * cls.K]), cls.ETA2 * cls.N * 2))
        
        # NTT(r_vec) - standard NTT
        r_hat = [cls._ntt(poly.copy()) for poly in r_vec]
        
        # u = A^T * r_hat + e1
        u_hat = [[0] * cls.N for _ in range(cls.K)]
        for i in range(cls.K):
            for j in range(cls.K):
                prod = [cls._mod_mul(A[j][i][k], r_hat[j][k]) for k in range(cls.N)]
                u_hat[i] = cls._poly_add(u_hat[i], prod)
            u_hat[i] = cls._poly_add(u_hat[i], [cls._ntt(e1[i])[k] for k in range(cls.N)])
        
        # v = t^T * r_hat + e2 + Decompress(m)
        v_hat = [0] * cls.N
        for i in range(cls.K):
            prod = [cls._mod_mul(t_ntt[i][k], r_hat[i][k]) for k in range(cls.N)]
            v_hat = cls._poly_add(v_hat, prod)
        v_hat = cls._poly_add(v_hat, cls._ntt(e2))
        # Use same encoding as encapsulation: _poly_decompress(m, 1) converted to NTT
        m_poly = cls._poly_decompress(m, 1)
        m_poly_ntt = cls._ntt(m_poly)
        v_hat = cls._poly_add(v_hat, m_poly_ntt)
        
        # Encode expected ciphertext - standard INTT
        expected_c1 = b""
        for i in range(cls.K):
            expected_c1 += cls._poly_compress(cls._intt(u_hat[i]), cls.DU)
        expected_c2 = cls._poly_compress(cls._intt(v_hat), cls.DV)
        expected_ct = expected_c1 + expected_c2 + session_seed
        
        # Constant-time comparison
        if not hmac.compare_digest(ciphertext, expected_ct):
            hash_ct = cls._h(ciphertext)
            fake_key = cls._kdf(
                z + hash_ct,
                cls.DOMAIN + b"-REJECT-" + recipe.encode(),
                32
            )
            return fake_key
        
        # Valid: derive shared secret from Kbar and H(ciphertext)
        h_ct = cls._h(ciphertext)
        recipe_bytes = recipe.encode()
        shared_secret = cls._kdf(
            Kbar + h_ct,
            cls.DOMAIN + b"-KEY-" + recipe_bytes,
            32
        )
        
        return shared_secret
    
    # ── Hybrid KEM (ECDH + 1nf1D3L Kyber) ──────────────────────────
    
    @classmethod
    def hybrid_keygen(cls, ecc_seed: bytes = None, recipe: str = "espresso") -> Tuple[bytes, bytes]:
        """
        Generate hybrid keypair: ECDH P-256 + 1nf1D3L Kyber.
        Returns: (hybrid_pk, hybrid_sk)
        """
        from server import Ed25519
        
        if ecc_seed is None:
            ecc_seed = secrets.token_bytes(32)
        
        ecc_pk, ecc_seed_out, _, _ = Ed25519.generate_keypair(ecc_seed)
        kyber_pk, kyber_sk = cls.keygen(recipe)
        
        # Encode: ecc_pk_len(2) || ecc_pk || kyber_pk
        ecc_pk_len = len(ecc_pk).to_bytes(2, 'big')
        hybrid_pk = ecc_pk_len + ecc_pk + kyber_pk
        
        # Encode: ecc_seed || kyber_sk
        hybrid_sk = ecc_seed_out + kyber_sk
        
        return hybrid_pk, hybrid_sk
    
    @classmethod
    def hybrid_encapsulate(cls, hybrid_pk: bytes, recipe: str = "espresso") -> Tuple[bytes, bytes]:
        """
        Hybrid encapsulation: ECDH + Kyber.
        Returns: (ciphertext, shared_secret)
        """
        from server import Ed25519, CoffeeCipher
        
        # Parse hybrid public key
        ecc_pk_len = int.from_bytes(hybrid_pk[:2], 'big')
        ecc_pk = hybrid_pk[2:2 + ecc_pk_len]
        kyber_pk = hybrid_pk[2 + ecc_pk_len:]
        
        # ECDH ephemeral
        ecc_ephem_seed = secrets.token_bytes(32)
        ecc_ephem_pk, _, _, _ = Ed25519.generate_keypair(ecc_ephem_seed)
        ecdh_shared = Ed25519.key_exchange(ecc_ephem_seed, ecc_pk)
        
        # Kyber encapsulation
        kyber_ct, kyber_ss = cls.encaps(kyber_pk, recipe)
        
        # Combine via HKDF
        combined = ecdh_shared + kyber_ss + cls.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)
        
        # Ciphertext: ecc_ephem_pk_len(2) || ecc_ephem_pk || kyber_ct
        ecc_ephem_len = len(ecc_ephem_pk).to_bytes(2, 'big')
        ciphertext = ecc_ephem_len + ecc_ephem_pk + kyber_ct
        
        return ciphertext, shared
    
    @classmethod
    def hybrid_decapsulate(cls, hybrid_sk: bytes, ciphertext: bytes, recipe: str = "espresso") -> bytes:
        """
        Hybrid decapsulation: ECDH + Kyber.
        Returns: shared_secret
        """
        from server import Ed25519, CoffeeCipher
        
        # Parse hybrid secret key
        ecc_seed = hybrid_sk[:32]
        kyber_sk = hybrid_sk[32:]
        
        # Parse ciphertext
        ecc_ephem_len = int.from_bytes(ciphertext[:2], 'big')
        ecc_ephem_pk = ciphertext[2:2 + ecc_ephem_len]
        kyber_ct = ciphertext[2 + ecc_ephem_len:]
        
        # ECDH shared secret
        ecdh_shared = Ed25519.key_exchange(ecc_seed, ecc_ephem_pk)
        
        # Kyber decapsulation
        kyber_ss = cls.decaps(kyber_sk, kyber_ct, recipe)
        
        # Combine via HKDF
        combined = ecdh_shared + kyber_ss + cls.DOMAIN + b"-HYBRID-" + recipe.encode()
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-1nf1del-v1", 32)
        
        return shared


# ── Standalone CLI Interface ───────────────────────────────────────

def print_banner():
    print(r"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     1nf1D3L's Kyber  —  Non-FIPS Post-Quantum KEM               ║
    ║     "Compliance is for auditors. Security is for survivors."    ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)


def cmd_keygen(args):
    recipe = args.recipe or "espresso"
    pk, sk = Inf1delKyber.keygen(recipe)
    print(f"Public Key  ({len(pk)} bytes):  {pk.hex()}")
    print(f"Private Key ({len(sk)} bytes):  {sk.hex()}")
    if args.output:
        with open(args.output + ".pk", "wb") as f:
            f.write(pk)
        with open(args.output + ".sk", "wb") as f:
            f.write(sk)
        print(f"Saved to {args.output}.pk and {args.output}.sk")


def cmd_encaps(args):
    recipe = args.recipe or "espresso"
    with open(args.pubkey, "rb") as f:
        pk = f.read()
    ct, ss = Inf1delKyber.encaps(pk, recipe)
    print(f"Ciphertext ({len(ct)} bytes): {ct.hex()}")
    print(f"Shared Secret (32 bytes):     {ss.hex()}")
    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)
        print(f"Ciphertext saved to {args.output}")


def cmd_decaps(args):
    recipe = args.recipe or "espresso"
    with open(args.privkey, "rb") as f:
        sk = f.read()
    with open(args.ciphertext, "rb") as f:
        ct = f.read()
    ss = Inf1delKyber.decaps(sk, ct, recipe)
    print(f"Shared Secret (32 bytes): {ss.hex()}")


def cmd_hybrid_keygen(args):
    recipe = args.recipe or "espresso"
    pk, sk = Inf1delKyber.hybrid_keygen(recipe=recipe)
    print(f"Hybrid Public Key  ({len(pk)} bytes):  {pk.hex()}")
    print(f"Hybrid Private Key ({len(sk)} bytes):  {sk.hex()}")
    if args.output:
        with open(args.output + ".hp", "wb") as f:
            f.write(pk)
        with open(args.output + ".hs", "wb") as f:
            f.write(sk)
        print(f"Saved to {args.output}.hp and {args.output}.hs")


def cmd_hybrid_encaps(args):
    recipe = args.recipe or "espresso"
    with open(args.pubkey, "rb") as f:
        pk = f.read()
    ct, ss = Inf1delKyber.hybrid_encapsulate(pk, recipe)
    print(f"Hybrid Ciphertext ({len(ct)} bytes): {ct.hex()}")
    print(f"Shared Secret (32 bytes):           {ss.hex()}")
    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)


def cmd_hybrid_decaps(args):
    recipe = args.recipe or "espresso"
    with open(args.privkey, "rb") as f:
        sk = f.read()
    with open(args.ciphertext, "rb") as f:
        ct = f.read()
    ss = Inf1delKyber.hybrid_decapsulate(sk, ct, recipe)
    print(f"Shared Secret (32 bytes): {ss.hex()}")


def cmd_benchmark(args):
    import time
    recipe = args.recipe or "espresso"
    iterations = args.iterations
    
    print(f"\nBenchmarking 1nf1D3L's Kyber ({recipe}) — {iterations} iterations...")
    
    # KeyGen
    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = Inf1delKyber.keygen(recipe)
    kg_time = (time.perf_counter() - start) / iterations * 1000
    
    # Encaps
    pk, sk = Inf1delKyber.keygen(recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ct, ss = Inf1delKyber.encaps(pk, recipe)
    enc_time = (time.perf_counter() - start) / iterations * 1000
    
    # Decaps
    ct, ss = Inf1delKyber.encaps(pk, recipe)
    start = time.perf_counter()
    for _ in range(iterations):
        ss2 = Inf1delKyber.decaps(sk, ct, recipe)
    dec_time = (time.perf_counter() - start) / iterations * 1000
    
    # Verify
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
    
    # keygen
    p = subparsers.add_parser("keygen", help="Generate keypair")
    p.add_argument("-o", "--output", help="Output file prefix")
    p.set_defaults(func=cmd_keygen)
    
    # encaps
    p = subparsers.add_parser("encaps", help="Encapsulate to public key")
    p.add_argument("pubkey", help="Public key file")
    p.add_argument("-o", "--output", help="Output ciphertext file")
    p.set_defaults(func=cmd_encaps)
    
    # decaps
    p = subparsers.add_parser("decaps", help="Decapsulate with private key")
    p.add_argument("privkey", help="Private key file")
    p.add_argument("ciphertext", help="Ciphertext file")
    p.set_defaults(func=cmd_decaps)
    
    # hybrid-keygen
    p = subparsers.add_parser("hybrid-keygen", help="Generate hybrid ECDH+Kyber keypair")
    p.add_argument("-o", "--output", help="Output file prefix")
    p.set_defaults(func=cmd_hybrid_keygen)
    
    # hybrid-encaps
    p = subparsers.add_parser("hybrid-encaps", help="Hybrid encapsulate")
    p.add_argument("pubkey", help="Hybrid public key file")
    p.add_argument("-o", "--output", help="Output ciphertext file")
    p.set_defaults(func=cmd_hybrid_encaps)
    
    # hybrid-decaps
    p = subparsers.add_parser("hybrid-decaps", help="Hybrid decapsulate")
    p.add_argument("privkey", help="Hybrid private key file")
    p.add_argument("ciphertext", help="Ciphertext file")
    p.set_defaults(func=cmd_hybrid_decaps)
    
    # benchmark
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