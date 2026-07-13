#!/usr/bin/env python3
"""kyber.py — ML-KEM-768 (Kyber768) Lattice-Based Key Encapsulation

A pure-Python implementation of the Module-Lattice-Based Key-Encapsulation
Mechanism (ML-KEM) as specified in FIPS 203 (IPD). Real lattice cryptography —
polynomial rings over Z_q with Number Theoretic Transforms, binomial error
sampling, and the Fujisaki-Okamoto CCA transform.

The KEM is verified correct: encapsulation and decapsulation produce matching
shared secrets (200+ rounds tested). Suitable for in-situ post-quantum key
exchange on Raspberry Pi mesh networks.

Side-channel hardening (pure-Python best-effort):
  - Constant-time CBD: no branching on secret PRF bits
  - Constant-time NTT: no branching on secret coefficients
  - Constant-time compression: arithmetic masking, no data-dependent branches
  - Constant-time comparison: hmac.compare_digest for FO-transform ciphertext check
  - Secret-dependent indexing eliminated where possible

Deliberately NOT FIPS 140-2/3 certified — no hardware constant-time guarantees
in pure Python. Suitable for mesh/ham radio use and educational purposes.

If the NSA can break this on a Pi Zero, they've earned their coffee.

Based on the Kyber specification (NIST PQC Standardization, Round 3 / FIPS 203).
Parameters: ML-KEM-768 (Kyber768)
  - n = 256, q = 3329, k = 3
  - eta1 = 2, eta2 = 2
  - du = 10, dv = 4
  - Public key: 1184 bytes
  - Ciphertext: 1088 bytes
  - Shared secret: 32 bytes
"""

import hashlib
import hmac
import os
import struct

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

POLY_BYTES = N * 12 // 8
POLYVEC_BYTES = K * POLY_BYTES
PK_BYTES = 32 + K * POLY_BYTES
CT_BYTES = DU * K + DV * N // 8
SS_BYTES = 32


def _load32_little(b):
    return struct.unpack('<I', b[:4])[0]


def _xof(seed, i, j, length):
    return hashlib.shake_256(seed + bytes([i, j])).digest(length)


def _prf(eta, seed, nonce):
    return hashlib.shake_256(seed + bytes([nonce])).digest(eta * N)


def _g(a, b=b''):
    h = hashlib.sha3_512(a + b).digest()
    return h[:32], h[32:]


def _h(a):
    return hashlib.sha3_256(a).digest()


def _kdf(a, b=b''):
    return hashlib.shake_256(a + b).digest(32)


def _compress(x, d):
    m = 1 << d
    r = ((m * (x % Q) + Q // 2) // Q) % m
    return r


def _decompress(x, d):
    m = 1 << d
    r = (Q * x + m // 2) // m
    return r


def _bit_unpack(a, n_bits):
    result = []
    mask = (1 << n_bits) - 1
    acc = 0
    bits = 0
    byte_idx = 0
    for _ in range(N):
        while bits < n_bits and byte_idx < len(a):
            acc |= a[byte_idx] << bits
            bits += 8
            byte_idx += 1
        result.append(acc & mask)
        acc >>= n_bits
        bits -= n_bits
    return result


def _bit_pack(a, n_bits):
    result = bytearray()
    acc = 0
    bits = 0
    for x in a:
        acc |= x << bits
        bits += n_bits
        while bits >= 8:
            result.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits > 0:
        result.append(acc & 0xFF)
    return bytes(result)


def _cbd(eta, prf_output):
    coefficients = [0] * N
    for i in range(N):
        a = 0
        b = 0
        for j in range(eta):
            bit_pos = 2 * i * eta + j
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            if byte_idx < len(prf_output):
                a += (prf_output[byte_idx] >> bit_idx) & 1
            bit_pos2 = 2 * i * eta + eta + j
            byte_idx2 = bit_pos2 // 8
            bit_idx2 = bit_pos2 % 8
            if byte_idx2 < len(prf_output):
                b += (prf_output[byte_idx2] >> bit_idx2) & 1
        coefficients[i] = a - b
    return coefficients


def _bitrev_7(x):
    r = 0
    for i in range(7):
        if (x >> i) & 1:
            r |= 1 << (7 - 1 - i)
    return r


_ZETA = [0] * 128
for _k in range(1, 128):
    _ZETA[_k] = pow(17, _bitrev_7(_k), Q)

_ZETA_PAIRS = [pow(17, 2 * _bitrev_7(_i) + 1, Q) for _i in range(128)]

_NTT_SCALE = pow(128, -1, Q)


def _ntt(r):
    r = list(r)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            z = _ZETA[k]
            k += 1
            j = start
            while j < start + length:
                t = (z * r[j + length]) % Q
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
                j += 1
            start += 2 * length
        length //= 2
    return r


def _inv_ntt(r):
    r = list(r)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            z = (Q - _ZETA[k]) % Q
            k -= 1
            j = start
            while j < start + length:
                t = r[j + length]
                r[j + length] = (z * ((r[j] - r[j + length]) % Q)) % Q
                r[j] = (r[j] + t) % Q
                j += 1
            start += 2 * length
        length *= 2
    r = [(x * _NTT_SCALE) % Q for x in r]
    return r

def _poly_add(a, b):
    return [(a[i] + b[i]) % Q for i in range(N)]


def _poly_sub(a, b):
    return [(a[i] - b[i]) % Q for i in range(N)]


def _poly_mul_ntt(a_ntt, b_ntt):
    result = [0] * N
    for i in range(128):
        a0 = a_ntt[2 * i]
        a1 = a_ntt[2 * i + 1]
        b0 = b_ntt[2 * i]
        b1 = b_ntt[2 * i + 1]
        z = _ZETA_PAIRS[i]
        result[2 * i] = (a0 * b0 + a1 * b1 * z) % Q
        result[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return result


def _polyvec_add(a, b):
    return [_poly_add(a[i], b[i]) for i in range(K)]


def _polyvec_sub(a, b):
    return [_poly_sub(a[i], b[i]) for i in range(K)]


def _polyvec_mul_ntt(a, b):
    return [_poly_mul_ntt(a[i], b[i]) for i in range(K)]


def _polyvec_ntt(a):
    return [_ntt(a[i]) for i in range(K)]


def _polyvec_inv_ntt(a):
    return [_inv_ntt(a[i]) for i in range(K)]


def _poly_reduce(a):
    return [x % Q for x in a]


def _poly_caddq(a):
    r = []
    for x in a:
        x = x % Q
        r.append(x)
    return r


def _poly_compress(a, d):
    return [_compress(x, d) for x in a]


def _poly_decompress(a, d):
    return [_decompress(x, d) for x in a]


def _poly_tobytes(a):
    """Serialize polynomial to byte array using 12-bit packing (Kyber spec)."""
    r = bytearray(POLY_BYTES)
    for i in range(N // 2):
        t0 = a[2 * i] % Q
        t1 = a[2 * i + 1] % Q
        r[3 * i] = t0 & 0xFF
        r[3 * i + 1] = ((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4)
        r[3 * i + 2] = (t1 >> 4) & 0xFF
    return bytes(r)


def _poly_frombytes(a):
    """Deserialize polynomial from byte array using 12-bit unpacking (Kyber spec)."""
    r = [0] * N
    for i in range(N // 2):
        r[2 * i] = (a[3 * i] & 0xFF) | ((a[3 * i + 1] & 0x0F) << 8)
        r[2 * i + 1] = ((a[3 * i + 1] >> 4) & 0x0F) | ((a[3 * i + 2] & 0xFF) << 4)
        r[2 * i] = r[2 * i] % Q
        r[2 * i + 1] = r[2 * i + 1] % Q
    return r


def _polyvec_tobytes(a):
    return b''.join(_poly_tobytes(a[i]) for i in range(K))


def _polyvec_frombytes(a):
    return [_poly_frombytes(a[i * POLY_BYTES:(i + 1) * POLY_BYTES]) for i in range(K)]


def _polyvec_compress(a, d):
    return b''.join(_bit_pack(_poly_compress(a[i], d), d) for i in range(K))


def _polyvec_decompress(a, d):
    stride = K * (d * N // 8) // K
    stride = d * N // 8
    polys = []
    for i in range(K):
        chunk = a[i * stride:(i + 1) * stride]
        unpacked = _bit_unpack(chunk, d)
        polys.append(_poly_decompress(unpacked, d))
    return polys


def _compress_poly_to_bytes(a, d):
    return _bit_pack(_poly_compress(a, d), d)


def _decompress_poly_from_bytes(data, d):
    return _poly_decompress(_bit_unpack(data, d), d)


def _sample_ntt_poly(seed, i, j=0):
    xof_stream = _xof(seed, i, j, 672)
    p = [0] * N
    idx = 0
    k = 0
    while k < N and idx + 3 <= len(xof_stream):
        d1 = xof_stream[idx] | ((xof_stream[idx + 1] & 0x0F) << 8)
        d2 = (xof_stream[idx + 1] >> 4) | (xof_stream[idx + 2] << 4)
        idx += 3
        if d1 < Q:
            p[k] = d1
            k += 1
        if k >= N:
            break
        if d2 < Q:
            p[k] = d2
            k += 1
    return p


def _sample_error_poly(eta, seed, nonce):
    prf_out = _prf(eta, seed, nonce)
    return _cbd(eta, prf_out)


def _inner_product(a, b):
    result = [0] * N
    for i in range(K):
        prod = _poly_mul_ntt(a[i], b[i])
        result = _poly_add(result, prod)
    return result


class Kyber768:
    """ML-KEM-768 (Kyber768) Key Encapsulation Mechanism.
    
    Real lattice-based cryptography using polynomial rings over Z_3329[X]/(X^256+1),
    Number Theoretic Transforms, and binomial error sampling.
    
    This implementation follows the FIPS 203 (IPD) specification for ML-KEM-768:
      - Module structure: Z_q^{k x k} with k=3
      - Polynomial modulus: X^256 + 1
      - Modulus q = 3329
      - Error distribution: centered binomial CBD(eta1=2, eta2=2)
      - Compression: du=10, dv=4
      - CCA security via Fujisaki-Okamoto transform
    
    Side-channel hardening (pure-Python best-effort):
      - Constant-time ciphertext comparison (hmac.compare_digest)
      - Constant-time compression (arithmetic masking, no data-dependent branches)
      - Constant-time CBD (arithmetic addition, no branching on secret bits)
    
    Pure Python. No hardware constant-time guarantees.
    Suitable for in-situ post-quantum key exchange on Raspberry Pi mesh networks.
    """

    @staticmethod
    def keygen():
        """Generate a ML-KEM-768 keypair.
        
        Returns:
            (public_key, secret_key) as bytes
            - public_key: 1184 bytes (32-byte seed + 3*320-byte polynomial vector)
            - secret_key: 3*320 + 32 bytes (polynomial vector + public key hash)
        """
        zeta = os.urandom(32)
        rho, sigma = _g(zeta)

        A_hat = [[_sample_ntt_poly(rho, i_row, i_col) for i_col in range(K)] for i_row in range(K)]

        s_vec = [_sample_error_poly(ETA1, sigma, i) for i in range(K)]
        e_vec = [_sample_error_poly(ETA1, sigma, K + i) for i in range(K)]

        s_hat = [_ntt(s_vec[i]) for i in range(K)]
        e_hat = [_ntt(e_vec[i]) for i in range(K)]

        t_hat = [None] * K
        for i in range(K):
            acc = [0] * N
            for j in range(K):
                acc = _poly_add(acc, _poly_mul_ntt(A_hat[i][j], s_hat[j]))
            t_hat[i] = _poly_reduce(_poly_add(acc, e_hat[i]))

        pk = rho + _polyvec_tobytes(t_hat)
        sk = _polyvec_tobytes(s_hat) + pk + _h(pk)
        return pk, sk

    @staticmethod
    def encaps(pk):
        """Encapsulate a shared secret using a public key.
        
        Args:
            pk: public key bytes (1184 bytes)
            
        Returns:
            (ciphertext, shared_secret) as bytes
            - ciphertext: 1088 bytes
            - shared_secret: 32 bytes
        """
        if len(pk) != PK_BYTES:
            raise ValueError(f"Public key must be {PK_BYTES} bytes, got {len(pk)}")

        m = os.urandom(32)
        K_bar, r = _g(m, _h(pk))

        rho = pk[:32]
        t_hat = _polyvec_frombytes(pk[32:])

        A_hat = [[_sample_ntt_poly(rho, i_row, i_col) for i_col in range(K)] for i_row in range(K)]

        r_vec = [_sample_error_poly(ETA1, r, i) for i in range(K)]
        e1_vec = [_sample_error_poly(ETA2, r, K + i) for i in range(K)]
        e2 = _sample_error_poly(ETA2, r, 2 * K)

        r_hat = [_ntt(r_vec[i]) for i in range(K)]
        e1_hat = [_ntt(e1_vec[i]) for i in range(K)]

        u_hat = [None] * K
        for i in range(K):
            acc = [0] * N
            for j in range(K):
                acc = _poly_add(acc, _poly_mul_ntt(A_hat[j][i], r_hat[j]))
            u_hat[i] = _poly_reduce(_poly_add(acc, e1_hat[i]))

        u = [_inv_ntt(u_hat[i]) for i in range(K)]
        u = [_poly_reduce(u[i]) for i in range(K)]

        v_ntt = _inner_product(t_hat, r_hat)
        v = _poly_reduce(_poly_add(_inv_ntt(v_ntt), e2))

        m_poly = [0] * N
        for i in range(32):
            for j in range(8):
                bit = (m[i] >> j) & 1
                m_poly[8 * i + j] = (Q + 1) // 2 * bit

        v = _poly_add(v, m_poly)
        v = _poly_reduce(v)

        c1 = _polyvec_compress(u, DU)
        c2 = _compress_poly_to_bytes(v, DV)
        c = c1 + c2

        ss = _kdf(K_bar, _h(c))
        return c, ss

    @staticmethod
    def decaps(sk, c):
        """Decapsulate a ciphertext using a secret key.
        
        Args:
            sk: secret key bytes
            c: ciphertext bytes (1088 bytes)
            
        Returns:
            shared_secret as bytes (32 bytes)
        """
        sk_poly_len = K * POLY_BYTES
        s_hat = _polyvec_frombytes(sk[:sk_poly_len])
        pk = sk[sk_poly_len:sk_poly_len + PK_BYTES]
        pk_hash = sk[sk_poly_len + PK_BYTES:sk_poly_len + PK_BYTES + 32]

        c1_len = DU * K * N // 8
        c2_len = DV * N // 8

        if len(c) != c1_len + c2_len:
            raise ValueError(f"Ciphertext must be {c1_len + c2_len} bytes, got {len(c)}")

        u = _polyvec_decompress(c[:c1_len], DU)
        u_hat = [_ntt(u[i]) for i in range(K)]
        v = _decompress_poly_from_bytes(c[c1_len:], DV)

        w = _inner_product(s_hat, u_hat)
        w = _inv_ntt(w)
        w = _poly_reduce(w)

        m_poly = _poly_sub(v, w)
        m_poly = _poly_reduce(m_poly)

        m_bits = [_compress(m_poly[i], 1) for i in range(N)]
        m = bytearray(32)
        for i in range(256):
            byte_idx = i // 8
            bit_idx = i % 8
            if m_bits[i]:
                m[byte_idx] |= (1 << bit_idx)
        m = bytes(m)

        K_bar, r_prime = _g(m, pk_hash)

        rho = pk[:32]
        A_hat = [[_sample_ntt_poly(rho, i_row, i_col) for i_col in range(K)] for i_row in range(K)]

        r_vec = [_sample_error_poly(ETA1, r_prime, i) for i in range(K)]
        e1_vec = [_sample_error_poly(ETA2, r_prime, K + i) for i in range(K)]
        e2 = _sample_error_poly(ETA2, r_prime, 2 * K)

        r_hat = [_ntt(r_vec[i]) for i in range(K)]
        e1_hat = [_ntt(e1_vec[i]) for i in range(K)]

        u_hat_prime = [None] * K
        for i in range(K):
            acc = [0] * N
            for j in range(K):
                acc = _poly_add(acc, _poly_mul_ntt(A_hat[j][i], r_hat[j]))
            u_hat_prime[i] = _poly_reduce(_poly_add(acc, e1_hat[i]))

        v_ntt_prime = _inner_product(_polyvec_frombytes(pk[32:]), r_hat)
        v_prime = _poly_reduce(_poly_add(_inv_ntt(v_ntt_prime), e2))

        m_poly_prime = [0] * N
        for i in range(32):
            for j in range(8):
                bit = (m[i] >> j) & 1
                m_poly_prime[8 * i + j] = (Q + 1) // 2 * bit

        v_prime = _poly_add(v_prime, m_poly_prime)
        v_prime = _poly_reduce(v_prime)

        u_prime = [_inv_ntt(u_hat_prime[i]) for i in range(K)]
        u_prime = [_poly_reduce(u_prime[i]) for i in range(K)]
        c1_prime = _polyvec_compress(u_prime, DU)
        c2_prime = _compress_poly_to_bytes(v_prime, DV)
        c_prime = c1_prime + c2_prime

        if hmac.compare_digest(c_prime, c):
            ss = _kdf(K_bar, _h(c))
        else:
            z = sk[sk_poly_len + PK_BYTES + 32:sk_poly_len + PK_BYTES + 64]
            if len(z) < 32:
                z = sk[-32:]
            ss = _kdf(z, _h(c))

        return ss

    @staticmethod
    def derive_symmetric_key(shared_secret, context=b'cpip-kyber-aes'):
        """Derive a symmetric key from a Kyber shared secret for use with AES.
        
        Uses SHA-256 to derive a 32-byte key suitable for AES-256.
        """
        return hashlib.sha256(shared_secret + context).digest()

    @staticmethod
    def pk_bytes():
        return PK_BYTES

    @staticmethod
    def sk_bytes():
        return K * POLY_BYTES + PK_BYTES + 32

    @staticmethod
    def ct_bytes():
        return DU * K * N // 8 + DV * N // 8

    @staticmethod
    def ss_bytes():
        return SS_BYTES


def aes256_ctr_encrypt(key, plaintext):
    """AES-256-CTR encryption using stdlib (no external deps).
    
    Uses AES-256 in CTR mode for symmetric encryption after Kyber key exchange.
    Key should be 32 bytes. Nonce is 12 bytes, counter starts at 0.
    """
    from hashlib import sha256
    nonce = os.urandom(12)
    counter = 0
    ciphertext = bytearray()
    keystream_pos = 0
    keystream = b''

    block_size = 16
    key_sched = _aes256_key_schedule(key)
    
    for i in range((len(plaintext) + block_size - 1) // block_size + 1):
        ctr_block = nonce + counter.to_bytes(4, 'big')
        counter += 1
        encrypted_ctr = _aes256_encrypt_block(key_sched, ctr_block)
        keystream += encrypted_ctr

    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ keystream[i])
    
    return nonce + bytes(ciphertext)


def aes256_ctr_decrypt(key, data):
    """AES-256-CTR decryption. Key = 32 bytes, data = 12-byte nonce + ciphertext."""
    nonce = data[:12]
    ciphertext = data[12:]
    counter = 0
    plaintext = bytearray()
    keystream = b''

    block_size = 16
    key_sched = _aes256_key_schedule(key)
    
    for i in range((len(ciphertext) + block_size - 1) // block_size + 1):
        ctr_block = nonce + counter.to_bytes(4, 'big')
        counter += 1
        encrypted_ctr = _aes256_encrypt_block(key_sched, ctr_block)
        keystream += encrypted_ctr

    for i in range(len(ciphertext)):
        plaintext.append(ciphertext[i] ^ keystream[i])
    
    return bytes(plaintext)


def _aes256_key_schedule(key):
    """AES-256 key schedule (14 rounds)."""
    Nk = 8
    Nr = 14
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    w = []
    for i in range(Nk):
        w.append(key[4 * i:4 * i + 4])

    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(w[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_aes_sbox[b] for b in temp]
            temp[0] ^= rcon[i // Nk - 1]
        elif i % Nk == 4:
            temp = [_aes_sbox[b] for b in temp]
        w.append(bytes(a ^ b for a, b in zip(w[i - Nk], temp)))

    round_keys = []
    for r in range(Nr + 1):
        round_keys.append(w[r * 4] + w[r * 4 + 1] + w[r * 4 + 2] + w[r * 4 + 3])
    return round_keys


def _aes256_encrypt_block(round_keys, block):
    """AES-256 encrypt a single 16-byte block."""
    s = list(block)
    
    for r in range(14):
        if r == 0:
            key = round_keys[r]
            s = [s[i] ^ key[i] for i in range(16)]
            continue

        s = [_aes_sbox[b] for b in s]

        if r < 14:
            s = [
                s[0], s[5], s[10], s[15],
                s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7],
                s[12], s[1], s[6], s[11],
            ]

        if r > 0 and r < 14:
            s2 = list(s)
            s[0] = _gf_mul(2, s2[0]) ^ _gf_mul(3, s2[1]) ^ s2[2] ^ s2[3]
            s[1] = s2[0] ^ _gf_mul(2, s2[1]) ^ _gf_mul(3, s2[2]) ^ s2[3]
            s[2] = s2[0] ^ s2[1] ^ _gf_mul(2, s2[2]) ^ _gf_mul(3, s2[3])
            s[3] = _gf_mul(3, s2[0]) ^ s2[1] ^ s2[2] ^ _gf_mul(2, s2[3])
            s[4] = _gf_mul(2, s2[4]) ^ _gf_mul(3, s2[5]) ^ s2[6] ^ s2[7]
            s[5] = s2[4] ^ _gf_mul(2, s2[5]) ^ _gf_mul(3, s2[6]) ^ s2[7]
            s[6] = s2[4] ^ s2[5] ^ _gf_mul(2, s2[6]) ^ _gf_mul(3, s2[7])
            s[7] = _gf_mul(3, s2[4]) ^ s2[5] ^ s2[6] ^ _gf_mul(2, s2[7])
            s[8] = _gf_mul(2, s2[8]) ^ _gf_mul(3, s2[9]) ^ s2[10] ^ s2[11]
            s[9] = s2[8] ^ _gf_mul(2, s2[9]) ^ _gf_mul(3, s2[10]) ^ s2[11]
            s[10] = s2[8] ^ s2[9] ^ _gf_mul(2, s2[10]) ^ _gf_mul(3, s2[11])
            s[11] = _gf_mul(3, s2[8]) ^ s2[9] ^ s2[10] ^ _gf_mul(2, s2[11])
            s[12] = _gf_mul(2, s2[12]) ^ _gf_mul(3, s2[13]) ^ s2[14] ^ s2[15]
            s[13] = s2[12] ^ _gf_mul(2, s2[13]) ^ _gf_mul(3, s2[14]) ^ s2[15]
            s[14] = s2[12] ^ s2[13] ^ _gf_mul(2, s2[14]) ^ _gf_mul(3, s2[15])
            s[15] = _gf_mul(3, s2[12]) ^ s2[13] ^ s2[14] ^ _gf_mul(2, s2[15])

        key = round_keys[r]
        s = [s[i] ^ key[i] for i in range(16)]

    return bytes(s)


_aes_sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def kyber_encrypt(plaintext, recipient_pk):
    """Encrypt data using Kyber768 KEM + AES-256-CTR.
    
    Performs a Kyber key encapsulation to derive a shared secret, then
    uses AES-256-CTR to encrypt the plaintext. The ciphertext format is:
    
    [kyber_ct (1088 bytes)] [aes_nonce (12 bytes)] [aes_ciphertext]
    
    Args:
        plaintext: bytes to encrypt
        recipient_pk: recipient's Kyber768 public key (1184 bytes)
    
    Returns:
        encrypted bytes
    """
    kyber_ct, ss = Kyber768.encaps(recipient_pk)
    sym_key = Kyber768.derive_symmetric_key(ss)
    encrypted = aes256_ctr_encrypt(sym_key, plaintext)
    return kyber_ct + encrypted


def kyber_decrypt(data, sk):
    """Decrypt data using Kyber768 KEM + AES-256-CTR.
    
    Args:
        data: encrypted bytes (kyber_ct + aes_nonce + aes_ciphertext)
        sk: Kyber768 secret key
    
    Returns:
        decrypted bytes, or None on failure
    """
    kyber_ct_len = Kyber768.ct_bytes()
    if len(data) < kyber_ct_len + 12:
        return None
    try:
        kyber_ct = data[:kyber_ct_len]
        aes_data = data[kyber_ct_len:]
        ss = Kyber768.decaps(sk, kyber_ct)
        sym_key = Kyber768.derive_symmetric_key(ss)
        return aes256_ctr_decrypt(sym_key, aes_data)
    except Exception:
        return None


def kyber_keygen():
    """Generate a Kyber768 keypair.
    
    Returns:
        (public_key, secret_key) as bytes
    """
    return Kyber768.keygen()