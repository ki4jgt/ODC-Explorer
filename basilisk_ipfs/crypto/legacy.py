"""Signature *verification* for non-Ed25519 libp2p key types: RSA
(PKCS#1 v1.5 / SHA-256), secp256k1 and ECDSA P-256. Peers using these keys
still exist on the public network (e.g. old ``Qm...`` peer IDs)."""

import hashlib
import hmac


# ---- minimal DER reader ---------------------------------------------------
def der_read(buf, off=0):
    """Returns (tag, content_bytes, next_offset)."""
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    return tag, buf[off:off + ln], off + ln


def der_seq(buf):
    out, off = [], 0
    while off < len(buf):
        t, c, off = der_read(buf, off)
        out.append((t, c))
    return out


# ---- RSA --------------------------------------------------------------------
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_public_from_pkix(der: bytes):
    _, spki, _ = der_read(der)
    items = der_seq(spki)
    bitstr = items[1][1]
    _, rsakey, _ = der_read(bitstr[1:])  # skip unused-bits byte
    (_, n), (_, e) = der_seq(rsakey)[:2]
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


def rsa_verify(pkix_der: bytes, msg: bytes, sig: bytes) -> bool:
    n, e = rsa_public_from_pkix(pkix_der)
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _SHA256_DIGEST_INFO + hashlib.sha256(msg).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


# ---- ECDSA on short Weierstrass curves ------------------------------------
class Curve:
    def __init__(self, p, a, b, gx, gy, n):
        self.p, self.a, self.b, self.G, self.n = p, a, b, (gx, gy), n

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        if P[0] == Q[0]:
            if (P[1] + Q[1]) % p == 0:
                return None
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p) % p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p

    def mul(self, k, P):
        R = None
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def decompress(self, data: bytes):
        if data[0] == 4:
            sz = (len(data) - 1) // 2
            return int.from_bytes(data[1:1 + sz], "big"), int.from_bytes(data[1 + sz:], "big")
        x = int.from_bytes(data[1:], "big")
        y2 = (x ** 3 + self.a * x + self.b) % self.p
        y = pow(y2, (self.p + 1) // 4, self.p)
        if y * y % self.p != y2:
            raise ValueError("invalid point")
        if (y & 1) != (data[0] & 1):
            y = self.p - y
        return x, y

    def verify(self, point, digest: bytes, der_sig: bytes) -> bool:
        try:
            _, body, _ = der_read(der_sig)
            (_, r), (_, s) = der_seq(body)
        except Exception:
            return False
        r, s = int.from_bytes(r, "big"), int.from_bytes(s, "big")
        n = self.n
        if not (0 < r < n and 0 < s < n):
            return False
        z = int.from_bytes(digest, "big")
        z >>= max(0, len(digest) * 8 - n.bit_length())
        w = pow(s, -1, n)
        X = self.add(self.mul(z * w % n, self.G), self.mul(r * w % n, point))
        return X is not None and X[0] % n == r


SECP256K1 = Curve(
    2 ** 256 - 2 ** 32 - 977, 0, 7,
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

P256 = Curve(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)


def secp256k1_verify(compressed_pub: bytes, msg: bytes, der_sig: bytes) -> bool:
    return SECP256K1.verify(SECP256K1.decompress(compressed_pub),
                            hashlib.sha256(msg).digest(), der_sig)


def ecdsa_p256_verify(pkix_der: bytes, msg: bytes, der_sig: bytes) -> bool:
    _, spki, _ = der_read(pkix_der)
    bitstr = der_seq(spki)[1][1]
    return P256.verify(P256.decompress(bitstr[1:]), hashlib.sha256(msg).digest(), der_sig)
