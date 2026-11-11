"""libp2p keys and peer IDs."""

import hashlib
import os

from . import multibase, multihash
from . import protobuf as pb
from .cid import CID
from .crypto import ed25519, legacy

RSA, ED25519, SECP256K1, ECDSA = 0, 1, 2, 3
_KEY_NAMES = {RSA: "RSA", ED25519: "Ed25519", SECP256K1: "Secp256k1", ECDSA: "ECDSA"}


class PublicKey:
    def __init__(self, key_type: int, data: bytes):
        self.type = key_type
        self.data = bytes(data)

    def to_protobuf(self) -> bytes:
        return pb.enc_varint(1, self.type) + pb.enc_bytes(2, self.data)

    @classmethod
    def from_protobuf(cls, buf: bytes) -> "PublicKey":
        m = pb.decode(buf)
        return cls(pb.first(m, 1), pb.first(m, 2, b""))

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            if self.type == ED25519:
                return ed25519.verify(self.data, msg, sig)
            if self.type == RSA:
                return legacy.rsa_verify(self.data, msg, sig)
            if self.type == SECP256K1:
                return legacy.secp256k1_verify(self.data, msg, sig)
            if self.type == ECDSA:
                return legacy.ecdsa_p256_verify(self.data, msg, sig)
        except Exception:
            return False
        return False

    def peer_id(self) -> "PeerID":
        return PeerID.from_public_key(self)

    def __eq__(self, other):
        return isinstance(other, PublicKey) and (self.type, self.data) == (other.type, other.data)

    def __repr__(self):
        return f"PublicKey({_KEY_NAMES.get(self.type, self.type)})"


class Ed25519PrivateKey:
    """The only private key type this library generates."""
    type = ED25519

    def __init__(self, seed: bytes = None):
        self.seed = seed or os.urandom(32)
        self._pub = ed25519.public_key(self.seed)

    @classmethod
    def from_protobuf(cls, buf: bytes) -> "Ed25519PrivateKey":
        m = pb.decode(buf)
        if pb.first(m, 1) != ED25519:
            raise ValueError("only Ed25519 private keys are supported")
        return cls(pb.first(m, 2)[:32])

    def to_protobuf(self) -> bytes:
        # libp2p serialises ed25519 private keys as seed || public
        return pb.enc_varint(1, ED25519) + pb.enc_bytes(2, self.seed + self._pub)

    def sign(self, msg: bytes) -> bytes:
        return ed25519.sign(self.seed, msg)

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(ED25519, self._pub)

    def peer_id(self) -> "PeerID":
        return self.public_key.peer_id()

    def save(self, path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(self.to_protobuf())

    @classmethod
    def load(cls, path) -> "Ed25519PrivateKey":
        with open(path, "rb") as f:
            return cls.from_protobuf(f.read())


class PeerID:
    __slots__ = ("multihash",)

    def __init__(self, mh: bytes):
        multihash.decode(mh)
        self.multihash = bytes(mh)

    @classmethod
    def from_public_key(cls, key: PublicKey) -> "PeerID":
        raw = key.to_protobuf()
        if len(raw) <= 42:
            return cls(multihash.digest(raw, "identity"))
        return cls(multihash.digest(raw, "sha2-256"))

    @classmethod
    def decode(cls, s) -> "PeerID":
        if isinstance(s, PeerID):
            return s
        if isinstance(s, (bytes, bytearray)):
            return cls(bytes(s))
        if s.startswith("Qm") or s.startswith("1"):
            return cls(multibase.b58decode(s))
        cid = CID.decode(s)
        if cid.codec != 0x72:
            raise ValueError("CID is not a libp2p-key")
        return cls(cid.multihash)

    def to_bytes(self) -> bytes:
        return self.multihash

    def to_cid(self) -> CID:
        return CID(1, "libp2p-key", self.multihash)

    def extract_public_key(self):
        """Returns the inlined public key for identity-multihash peer IDs."""
        code, digest = multihash.decode(self.multihash)
        return PublicKey.from_protobuf(digest) if code == 0 else None

    def matches(self, key: PublicKey) -> bool:
        return PeerID.from_public_key(key) == self

    def __str__(self):
        return multibase.b58encode(self.multihash)

    def __repr__(self):
        return f"PeerID({self})"

    def __eq__(self, other):
        return isinstance(other, PeerID) and self.multihash == other.multihash

    def __hash__(self):
        return hash(self.multihash)

    def dht_key(self) -> bytes:
        return hashlib.sha256(self.multihash).digest()
