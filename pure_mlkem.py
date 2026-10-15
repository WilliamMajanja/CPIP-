"""Standard-library-only 1nf1D3L ML-KEM-size KEM backend.

This module mirrors the bundled NumPy implementation in ``inf1del_kyber`` for
ML-KEM-512/768/1024 and experimental 1nf1D3L-2048/4096 parameter sizes. It intentionally retains the 1nf1D3L
domain separation, eta1=3 noise at all sizes, and 32-byte ciphertext suffix;
it is not FIPS 203 interoperable or validated. Only Python's standard library
is imported, making this a dependency-free fallback, not a constant-time
cryptographic implementation.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

Q = 3329
N = 256
ROOT = 17
N_INV = pow(N, -1, Q)
DOMAIN = b"1NF1D3L-KYBER-V1"

PARAMS = {
    512: {"K": 2, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4},
    768: {"K": 3, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4},
    1024: {"K": 4, "ETA1": 3, "ETA2": 2, "DU": 11, "DV": 5},
    # Experimental module ranks; these are not FIPS 203 security levels.
    2048: {"K": 8, "ETA1": 3, "ETA2": 2, "DU": 12, "DV": 5},
    4096: {"K": 16, "ETA1": 3, "ETA2": 2, "DU": 13, "DV": 5},
}


def _bit_reverse_indices() -> list[int]:
    result = []
    for value in range(N):
        reversed_value = 0
        bit = value
        for _ in range(8):
            reversed_value = (reversed_value << 1) | (bit & 1)
            bit >>= 1
        result.append(reversed_value)
    return result


_BIT_REVERSE = _bit_reverse_indices()


def _ntt(poly: list[int] | tuple[int, ...]) -> list[int]:
    a = [int(poly[i]) % Q for i in _BIT_REVERSE]
    length = 2
    stage = 0
    while length <= N:
        half = length // 2
        root = pow(ROOT, 256 // length, Q)
        twiddle = 1
        for offset in range(0, N, length):
            w = 1
            for j in range(half):
                u = a[offset + j]
                v = (a[offset + j + half] * w) % Q
                a[offset + j] = (u + v) % Q
                a[offset + j + half] = (u - v) % Q
                w = (w * root) % Q
        length <<= 1
        stage += 1
    return a


def _intt(poly: list[int] | tuple[int, ...]) -> list[int]:
    a = [int(value) % Q for value in poly]
    length = N
    while length >= 2:
        half = length // 2
        root = pow(ROOT, -(256 // length), Q)
        for offset in range(0, N, length):
            w = 1
            for j in range(half):
                u = a[offset + j]
                v = a[offset + j + half]
                a[offset + j] = (u + v) % Q
                a[offset + j + half] = ((u - v) * w) % Q
                w = (w * root) % Q
        length >>= 1
    a = [a[i] for i in _BIT_REVERSE]
    return [(value * N_INV) % Q for value in a]


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _cbd(buf: bytes, eta: int) -> list[int]:
    needed_bits = N * 2 * eta
    if len(buf) * 8 < needed_bits:
        buf += b"\x00" * ((needed_bits - len(buf) * 8 + 7) // 8)
    result = []
    for i in range(N):
        start = i * 2 * eta
        pos = sum((buf[(start + j) // 8] >> ((start + j) % 8)) & 1 for j in range(eta))
        neg_start = start + eta
        neg = sum((buf[(neg_start + j) // 8] >> ((neg_start + j) % 8)) & 1 for j in range(eta))
        result.append((pos - neg) % Q)
    return result


def _compress_value(value: int, bits: int) -> int:
    return ((value * (1 << bits) + 1664) // Q) & ((1 << bits) - 1)


def _decompress_value(value: int, bits: int) -> int:
    return ((value * Q) + (1 << (bits - 1))) >> bits


def _poly_compress(poly: list[int], bits: int) -> bytes:
    packed = bytearray((N * bits + 7) // 8)
    bit_pos = 0
    for coeff in poly:
        value = _compress_value(coeff, bits)
        for bit in range(bits):
            if (value >> bit) & 1:
                packed[bit_pos >> 3] |= 1 << (bit_pos & 7)
            bit_pos += 1
    return bytes(packed)


def _poly_decompress(data: bytes, bits: int) -> list[int]:
    if len(data) * 8 < N * bits:
        raise ValueError("Compressed polynomial is truncated")
    poly = []
    bit_pos = 0
    for _ in range(N):
        value = 0
        for bit in range(bits):
            value |= ((data[bit_pos >> 3] >> (bit_pos & 7)) & 1) << bit
            bit_pos += 1
        poly.append(_decompress_value(value, bits) % Q)
    return poly


def _hash_h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _hash_g(data: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.shake_256(data).digest(64)
    return digest[:32], digest[32:]


def _prf(key: bytes, nonce: bytes, length: int) -> bytes:
    return hashlib.shake_256(key + nonce).digest(length)


def _kdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(DOMAIN + b"-PRK", ikm, hashlib.sha3_256).digest()
    output = bytearray()
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha3_256).digest()
        output.extend(previous)
    return bytes(output[:length])


def _generate_matrix(rho: bytes, k: int) -> list[list[int]]:
    matrix = []
    for i in range(k):
        for j in range(k):
            xof_input = rho + bytes((j, i))
            stream = hashlib.shake_256(DOMAIN + b"-MATRIX-" + xof_input).digest(N * 12)
            coeffs = []
            cursor = 0
            for cursor in range(0, len(stream) - 1, 2):
                value = stream[cursor] | (stream[cursor + 1] << 8)
                if value < Q * 2:
                    coeffs.append(value % Q)
                    if len(coeffs) == N:
                        break
            while len(coeffs) < N:
                retry = 0
                while True:
                    more = hashlib.shake_256(
                        xof_input + b"-EXT-" + len(coeffs).to_bytes(2, "little")
                        + retry.to_bytes(4, "little")
                    ).digest(128)
                    retry += 1
                    if any(
                        (more[i] | (more[i + 1] << 8)) < Q * 2
                        for i in range(0, len(more) - 1, 2)
                    ):
                        break
                for cursor in range(0, len(more) - 1, 2):
                    value = more[cursor] | (more[cursor + 1] << 8)
                    if value < Q * 2:
                        coeffs.append(value % Q)
                        if len(coeffs) == N:
                            break
            matrix.append(_ntt(coeffs))
    return matrix


def _pointwise_accumulate(left: list[list[int]], right: list[list[int]]) -> list[int]:
    result = [0] * N
    for a, b in zip(left, right):
        result = [(x + (u * v) % Q) % Q for x, u, v in zip(result, a, b)]
    return result


def keygen(size: int = 768, recipe: str = "espresso") -> tuple[bytes, bytes]:
    if size not in PARAMS:
        raise ValueError("Unsupported KEM size; choose 512, 768, 1024, 2048, or 4096")
    p = PARAMS[size]
    k, eta1 = p["K"], p["ETA1"]
    d, z = secrets.token_bytes(32), secrets.token_bytes(32)
    rho, sigma = _hash_g(d)
    matrix = _generate_matrix(rho, k)
    s = [_cbd(_prf(sigma, bytes([i]), eta1 * N * 2), eta1) for i in range(k)]
    e = [_cbd(_prf(sigma, bytes([k + i]), eta1 * N * 2), eta1) for i in range(k)]
    s_ntt = [_ntt(poly) for poly in s]
    e_ntt = [_ntt(poly) for poly in e]
    t_ntt = []
    for i in range(k):
        row = matrix[i * k:(i + 1) * k]
        product = _pointwise_accumulate(row, s_ntt)
        t_ntt.append(_poly_add(product, e_ntt[i]))
    public_key = rho + b"".join(_poly_compress(poly, 12) for poly in t_ntt)
    secret_key = b"".join(_poly_compress(poly, 12) for poly in s) + public_key + _hash_h(public_key) + z
    return public_key, secret_key


def encaps(public_key: bytes, size: int = 768, recipe: str = "espresso") -> tuple[bytes, bytes]:
    if size not in PARAMS:
        raise ValueError("Unsupported KEM size; choose 512, 768, 1024, 2048, or 4096")
    p = PARAMS[size]
    k, eta1, eta2, du, dv = p["K"], p["ETA1"], p["ETA2"], p["DU"], p["DV"]
    expected_pk_len = 32 + k * 384
    if len(public_key) != expected_pk_len:
        raise ValueError(f"Invalid public key length: {len(public_key)} != {expected_pk_len}")
    rho, compressed = public_key[:32], public_key[32:]
    matrix = _generate_matrix(rho, k)
    t_ntt = [_poly_decompress(compressed[i * 384:(i + 1) * 384], 12) for i in range(k)]
    message = secrets.token_bytes(32)
    kbar = _hash_h(message + _hash_h(public_key))
    r = hashlib.shake_256(kbar).digest(32)
    r_vec = [_cbd(_prf(r, bytes([i]), eta1 * N * 2), eta1) for i in range(k)]
    e1 = [_cbd(_prf(r, bytes([k + i]), eta1 * N * 2), eta1) for i in range(k)]
    e2 = _cbd(_prf(r, bytes([2 * k]), eta2 * N * 2), eta2)
    r_ntt = [_ntt(poly) for poly in r_vec]
    u_ntt = []
    for i in range(k):
        col = [matrix[j * k + i] for j in range(k)]
        u_ntt.append(_poly_add(_pointwise_accumulate(col, r_ntt), _ntt(e1[i])))
    v_ntt = _poly_add(_pointwise_accumulate(t_ntt, r_ntt), _ntt(e2))
    message_poly = _ntt(_poly_decompress(message, 1))
    v_ntt = _poly_add(v_ntt, message_poly)
    ciphertext = b"".join(_poly_compress(_intt(poly), du) for poly in u_ntt)
    ciphertext += _poly_compress(_intt(v_ntt), dv) + secrets.token_bytes(32)
    h_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
    shared = _kdf(kbar + h_ct, DOMAIN + b"-KEY-" + recipe.encode(), 32)
    return ciphertext, shared


def decaps(secret_key: bytes, ciphertext: bytes, size: int = 768, recipe: str = "espresso") -> bytes:
    if size not in PARAMS:
        raise ValueError("Unsupported KEM size; choose 512, 768, 1024, 2048, or 4096")
    p = PARAMS[size]
    k, eta1, eta2, du, dv = p["K"], p["ETA1"], p["ETA2"], p["DU"], p["DV"]
    public_key_len = 32 + k * 384
    expected_sk_len = k * 384 + public_key_len + 32 + 32
    h_ct = hashlib.sha3_256(DOMAIN + ciphertext).digest()
    if len(secret_key) != expected_sk_len:
        raise ValueError(f"Invalid secret key length: {len(secret_key)} != {expected_sk_len}")
    s = [_poly_decompress(secret_key[i * 384:(i + 1) * 384], 12) for i in range(k)]
    offset = k * 384
    public_key = secret_key[offset:offset + public_key_len]
    offset += public_key_len
    stored_h_pk = secret_key[offset:offset + 32]
    z = secret_key[offset + 32:offset + 64]
    reject = lambda: _kdf(z + h_ct, DOMAIN + b"-REJECT-" + recipe.encode(), 32)
    if _hash_h(public_key) != stored_h_pk:
        return reject()
    c1_len = k * (N * du // 8)
    c2_len = N * dv // 8
    if len(ciphertext) != c1_len + c2_len + 32:
        return reject()
    c1, c2 = ciphertext[:c1_len], ciphertext[c1_len:c1_len + c2_len]
    session_seed = ciphertext[-32:]
    del session_seed  # retained in the custom ciphertext format and hash-bound
    rho, compressed_t = public_key[:32], public_key[32:]
    matrix = _generate_matrix(rho, k)
    t_ntt = [_poly_decompress(compressed_t[i * 384:(i + 1) * 384], 12) for i in range(k)]
    u_ntt = []
    poly_len = N * du // 8
    for i in range(k):
        u_poly = _poly_decompress(c1[i * poly_len:(i + 1) * poly_len], du)
        u_ntt.append(_ntt(u_poly))
    v_poly = _poly_decompress(c2, dv)
    v_ntt = _ntt(v_poly)
    s_ntt = [_ntt(poly) for poly in s]
    s_t_u = _pointwise_accumulate(s_ntt, u_ntt)
    message_poly = _poly_sub(v_ntt, s_t_u)
    message_bits = [int(Q // 4 <= coeff <= 3 * Q // 4) for coeff in _intt(message_poly)]
    packed_message = bytearray(32)
    for i, bit in enumerate(message_bits):
        packed_message[i >> 3] |= bit << (i & 7)
    message = bytes(packed_message)
    kbar = _hash_h(message + _hash_h(public_key))
    r = hashlib.shake_256(kbar).digest(32)
    r_vec = [_cbd(_prf(r, bytes([i]), eta1 * N * 2), eta1) for i in range(k)]
    e1 = [_cbd(_prf(r, bytes([k + i]), eta1 * N * 2), eta1) for i in range(k)]
    e2 = _cbd(_prf(r, bytes([2 * k]), eta2 * N * 2), eta2)
    r_ntt = [_ntt(poly) for poly in r_vec]
    u_hat = []
    for i in range(k):
        col = [matrix[j * k + i] for j in range(k)]
        u_hat.append(_poly_add(_pointwise_accumulate(col, r_ntt), _ntt(e1[i])))
    v_hat = _poly_add(_pointwise_accumulate(t_ntt, r_ntt), _ntt(e2))
    v_hat = _poly_add(v_hat, _ntt(_poly_decompress(message, 1)))
    expected = b"".join(_poly_compress(_intt(poly), du) for poly in u_hat)
    expected += _poly_compress(_intt(v_hat), dv) + ciphertext[-32:]
    if hmac.compare_digest(ciphertext, expected):
        return _kdf(kbar + h_ct, DOMAIN + b"-KEY-" + recipe.encode(), 32)
    return reject()


class PurePythonMLKEM:
    """Convenience adapter matching the bundled KEM API."""

    def __init__(self, size: int = 768, recipe: str = "espresso"):
        if size not in PARAMS:
            raise ValueError("Unsupported KEM size; choose 512, 768, 1024, 2048, or 4096")
        self.size = size
        self.recipe = recipe
        self.K = PARAMS[size]["K"]
        self.public_key_size = 32 + self.K * 384
        self.secret_key_size = self.public_key_size + self.K * 384 + 64
        self.ciphertext_size = self.K * (N * PARAMS[size]["DU"] // 8) + N * PARAMS[size]["DV"] // 8 + 32
        self.shared_key_size = 32

    def keygen(self) -> tuple[bytes, bytes]:
        return keygen(self.size, self.recipe)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return encaps(public_key, self.size, self.recipe)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return decaps(secret_key, ciphertext, self.size, self.recipe)
