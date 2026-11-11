"""Ed25519 signatures (RFC 8032), pure Python."""

import hashlib
import os

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
SQRT_M1 = pow(2, (p - 1) // 4, p)


def _inv(x):
    return pow(x, p - 2, p)


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * SQRT_M1 % p
    if (x * x - x2) % p:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)
IDENT = (0, 1, 1, 0)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F % p, G_ * H % p, F * G_ % p, E * H % p)


def _mul(s, P):
    Q = IDENT
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % p, P[1] * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(s):
    if len(s) != 32:
        raise ValueError("invalid point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        raise ValueError("invalid point")
    return (x, y, 1, x * y % p)


def _sha512_int(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def py_public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    a, _ = _expand(seed)
    return _compress(_mul(a, G))


def py_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _compress(_mul(a, G))
    r = _sha512_int(prefix, msg) % L
    R = _compress(_mul(r, G))
    h = _sha512_int(R, A, msg) % L
    s = (r + h * a) % L
    return R + s.to_bytes(32, "little")


def py_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    try:
        A = _decompress(public)
        R = _decompress(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    h = _sha512_int(sig[:32], public, msg) % L
    return _eq(_mul(s, G), _add(R, _mul(h, A)))


def generate_seed() -> bytes:
    return os.urandom(32)


# ---- use OpenSSL when available ---------------------------------------------
from . import _openssl as _ossl  # noqa: E402

if _ossl.AVAILABLE:
    public_key = _ossl.ed25519_public
    sign = _ossl.ed25519_sign
    verify = _ossl.ed25519_verify
else:
    public_key, sign, verify = py_public_key, py_sign, py_verify
