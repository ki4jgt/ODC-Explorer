"""libp2p Noise secure channel: Noise_XX_25519_ChaChaPoly_SHA256.

Spec: https://github.com/libp2p/specs/blob/master/noise/README.md
"""

import hashlib
import hmac
import struct
import threading

from .. import protobuf as pb
from ..crypto import chacha20poly1305 as aead
from ..crypto import x25519
from ..keys import PeerID, PublicKey

PROTOCOL_ID = "/noise"
_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
_SIG_PREFIX = b"noise-libp2p-static-key:"
MAX_FRAME = 65535
MAX_PLAINTEXT = MAX_FRAME - 16


class HandshakeError(Exception):
    pass


def _hkdf(ck, ikm, n=2):
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    o1 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    if n == 1:
        return (o1,)
    o2 = hmac.new(temp, o1 + b"\x02", hashlib.sha256).digest()
    return o1, o2


def _nonce(n):
    return b"\0\0\0\0" + struct.pack("<Q", n)


class CipherState:
    def __init__(self, key=None):
        self.k = key
        self.n = 0

    def encrypt(self, ad, pt):
        if self.k is None:
            return pt
        ct = aead.encrypt(self.k, _nonce(self.n), pt, ad)
        self.n += 1
        return ct

    def decrypt(self, ad, ct):
        if self.k is None:
            return ct
        pt = aead.decrypt(self.k, _nonce(self.n), ct, ad)
        self.n += 1
        return pt


class SymmetricState:
    def __init__(self):
        self.h = _NAME  # exactly HASHLEN bytes, so used directly
        self.ck = self.h
        self.cipher = CipherState()
        self.mix_hash(b"")  # empty prologue

    def mix_hash(self, data):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm):
        self.ck, k = _hkdf(self.ck, ikm)
        self.cipher = CipherState(k)

    def encrypt_and_hash(self, pt):
        ct = self.cipher.encrypt(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct):
        pt = self.cipher.decrypt(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self):
        k1, k2 = _hkdf(self.ck, b"")
        return CipherState(k1), CipherState(k2)


def _make_payload(identity, static_pub):
    sig = identity.sign(_SIG_PREFIX + static_pub)
    return pb.enc_bytes(1, identity.public_key.to_protobuf()) + pb.enc_bytes(2, sig)


def _check_payload(payload, remote_static):
    m = pb.decode(payload)
    key_pb, sig = pb.first(m, 1), pb.first(m, 2)
    if key_pb is None or sig is None:
        raise HandshakeError("handshake payload missing identity")
    key = PublicKey.from_protobuf(key_pb)
    if not key.verify(_SIG_PREFIX + remote_static, sig):
        raise HandshakeError("invalid static key signature")
    return key


class SecureConnection:
    """An encrypted, framed duplex byte stream over a raw connection."""

    def __init__(self, raw, send_cs, recv_cs, local_peer, remote_peer, remote_key):
        self.raw = raw
        self._send = send_cs
        self._recv = recv_cs
        self.local_peer = local_peer
        self.remote_peer = remote_peer
        self.remote_key = remote_key
        self._buf = bytearray()
        self._wlock = threading.Lock()

    def write(self, data: bytes):
        data = memoryview(bytes(data))
        with self._wlock:
            out = []
            for i in range(0, len(data), MAX_PLAINTEXT):
                ct = self._send.encrypt(b"", bytes(data[i:i + MAX_PLAINTEXT]))
                out.append(struct.pack(">H", len(ct)) + ct)
            self.raw.write(b"".join(out))

    def _read_frame(self):
        ln = struct.unpack(">H", self.raw.read_exact(2))[0]
        self._buf += self._recv.decrypt(b"", self.raw.read_exact(ln))

    def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._read_frame()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read_some(self) -> bytes:
        if not self._buf:
            self._read_frame()
        out = bytes(self._buf)
        self._buf.clear()
        return out

    def close(self):
        self.raw.close()


def _send_msg(raw, payload):
    raw.write(struct.pack(">H", len(payload)) + payload)


def _recv_msg(raw):
    ln = struct.unpack(">H", raw.read_exact(2))[0]
    return raw.read_exact(ln)


def handshake_initiator(raw, identity, expected_peer: PeerID = None) -> SecureConnection:
    ss = SymmetricState()
    s_priv = x25519.generate_private()
    s_pub = x25519.public_key(s_priv)
    e_priv = x25519.generate_private()
    e_pub = x25519.public_key(e_priv)

    # -> e
    ss.mix_hash(e_pub)
    _send_msg(raw, e_pub + ss.encrypt_and_hash(b""))

    # <- e, ee, s, es
    msg = _recv_msg(raw)
    if len(msg) < 32 + 48:
        raise HandshakeError("short noise message 2")
    re = msg[:32]
    ss.mix_hash(re)
    ss.mix_key(x25519.shared(e_priv, re))
    rs = ss.decrypt_and_hash(msg[32:80])
    ss.mix_key(x25519.shared(e_priv, rs))
    payload = ss.decrypt_and_hash(msg[80:])
    remote_key = _check_payload(payload, rs)
    remote_peer = remote_key.peer_id()
    if expected_peer is not None and remote_peer != expected_peer:
        raise HandshakeError(f"peer ID mismatch: expected {expected_peer}, got {remote_peer}")

    # -> s, se
    enc_s = ss.encrypt_and_hash(s_pub)
    ss.mix_key(x25519.shared(s_priv, re))
    enc_p = ss.encrypt_and_hash(_make_payload(identity, s_pub))
    _send_msg(raw, enc_s + enc_p)

    c1, c2 = ss.split()
    return SecureConnection(raw, c1, c2, identity.peer_id(), remote_peer, remote_key)


def handshake_responder(raw, identity) -> SecureConnection:
    ss = SymmetricState()
    s_priv = x25519.generate_private()
    s_pub = x25519.public_key(s_priv)
    e_priv = x25519.generate_private()
    e_pub = x25519.public_key(e_priv)

    # -> e
    msg = _recv_msg(raw)
    if len(msg) < 32:
        raise HandshakeError("short noise message 1")
    re = msg[:32]
    ss.mix_hash(re)
    ss.decrypt_and_hash(msg[32:])

    # <- e, ee, s, es
    ss.mix_hash(e_pub)
    ss.mix_key(x25519.shared(e_priv, re))
    enc_s = ss.encrypt_and_hash(s_pub)
    ss.mix_key(x25519.shared(s_priv, re))
    enc_p = ss.encrypt_and_hash(_make_payload(identity, s_pub))
    _send_msg(raw, e_pub + enc_s + enc_p)

    # -> s, se
    msg = _recv_msg(raw)
    if len(msg) < 48:
        raise HandshakeError("short noise message 3")
    rs = ss.decrypt_and_hash(msg[:48])
    ss.mix_key(x25519.shared(e_priv, rs))
    payload = ss.decrypt_and_hash(msg[48:])
    remote_key = _check_payload(payload, rs)

    c1, c2 = ss.split()
    return SecureConnection(raw, c2, c1, identity.peer_id(), remote_key.peer_id(), remote_key)
