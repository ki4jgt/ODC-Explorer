"""X25519 Diffie-Hellman (RFC 7748), pure Python."""

import os

P = 2 ** 255 - 19
A24 = 121665


def _clamp(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def scalarmult(k: bytes, u: bytes) -> bytes:
    if len(k) != 32 or len(u) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    k = _clamp(k)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = x1 * (DA - CB) ** 2 % P
        x2 = AA * BB % P
        z2 = E * (AA + A24 * E) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def generate_private() -> bytes:
    return os.urandom(32)


def py_public_key(priv: bytes) -> bytes:
    return scalarmult(priv, BASE)


def py_shared(priv: bytes, peer_pub: bytes) -> bytes:
    out = scalarmult(priv, peer_pub)
    if out == b"\0" * 32:
        raise ValueError("x25519 produced all-zero shared secret")
    return out


# ---- use OpenSSL when available ---------------------------------------------
from . import _openssl as _ossl  # noqa: E402

if _ossl.AVAILABLE:
    public_key = _ossl.x25519_public
    shared = _ossl.x25519_shared
else:
    public_key, shared = py_public_key, py_shared
