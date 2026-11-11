"""Content Identifiers (CIDv0 and CIDv1)."""

from . import multibase, multihash, varint
from .multicodec import code as _code, name as _name


class CID:
    __slots__ = ("version", "codec", "multihash")

    def __init__(self, version: int, codec, mh: bytes):
        codec = _code(codec)
        if version == 0:
            c, d = multihash.decode(mh)
            if codec != 0x70 or c != 0x12 or len(d) != 32:
                raise ValueError("CIDv0 must be dag-pb + sha2-256")
        elif version != 1:
            raise ValueError(f"unsupported CID version {version}")
        else:
            multihash.decode(mh)
        self.version = version
        self.codec = codec
        self.multihash = bytes(mh)

    # ---- construction -------------------------------------------------
    @classmethod
    def decode(cls, value) -> "CID":
        """Parse a CID from a string, bytes, or another CID."""
        if isinstance(value, CID):
            return value
        if isinstance(value, (bytes, bytearray, memoryview)):
            return cls.from_bytes(bytes(value))
        if isinstance(value, str):
            return cls.from_string(value)
        raise TypeError(f"cannot make CID from {type(value).__name__}")

    @classmethod
    def from_string(cls, s: str) -> "CID":
        s = s.strip()
        if s.startswith("/ipfs/"):
            s = s[6:].split("/", 1)[0]
        if len(s) == 46 and s.startswith("Qm"):
            return cls(0, 0x70, multibase.b58decode(s))
        return cls.from_bytes(multibase.decode(s))

    @classmethod
    def from_bytes(cls, b: bytes) -> "CID":
        cid, end = cls.read(b, 0)
        if end != len(b):
            raise ValueError("trailing bytes after CID")
        return cid

    @classmethod
    def read(cls, b: bytes, offset: int = 0):
        """Parse a binary CID at ``offset``; returns ``(cid, new_offset)``."""
        if len(b) - offset >= 34 and b[offset] == 0x12 and b[offset + 1] == 0x20:
            return cls(0, 0x70, b[offset:offset + 34]), offset + 34
        version, off = varint.decode(b, offset)
        if version != 1:
            raise ValueError(f"unsupported CID version {version}")
        codec, off = varint.decode(b, off)
        mh, off = multihash.read(b, off)
        return cls(1, codec, mh), off

    @classmethod
    def from_data(cls, data: bytes, codec="raw", version: int = 1, hash_fn="sha2-256") -> "CID":
        return cls(version, codec, multihash.digest(data, hash_fn))

    # ---- encoding -----------------------------------------------------
    def to_bytes(self) -> bytes:
        if self.version == 0:
            return self.multihash
        return varint.encode(1) + varint.encode(self.codec) + self.multihash

    __bytes__ = to_bytes

    def encode(self, base: str = None) -> str:
        if self.version == 0:
            if base not in (None, "base58btc"):
                raise ValueError("CIDv0 can only be base58btc")
            return multibase.b58encode(self.multihash)
        return multibase.encode(self.to_bytes(), base or "base32")

    def __str__(self):
        return self.encode()

    def __repr__(self):
        return f"CID({self.encode()!r})"

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = CID.decode(other)
            except ValueError:
                return False
        return (isinstance(other, CID) and self.version == other.version
                and self.codec == other.codec and self.multihash == other.multihash)

    def __hash__(self):
        return hash((self.version, self.codec, self.multihash))

    # ---- helpers ------------------------------------------------------
    @property
    def codec_name(self) -> str:
        return _name(self.codec)

    @property
    def hash_code(self) -> int:
        return multihash.decode(self.multihash)[0]

    @property
    def digest(self) -> bytes:
        return multihash.decode(self.multihash)[1]

    def to_v1(self) -> "CID":
        return self if self.version == 1 else CID(1, self.codec, self.multihash)

    def to_v0(self) -> "CID":
        return self if self.version == 0 else CID(0, self.codec, self.multihash)

    def prefix(self) -> bytes:
        """Bitswap 1.1+ CID prefix: version, codec, hash code, digest length."""
        c, d = multihash.decode(self.multihash)
        return (varint.encode(self.version) + varint.encode(self.codec)
                + varint.encode(c) + varint.encode(len(d)))

    @classmethod
    def from_prefix(cls, prefix: bytes, data: bytes) -> "CID":
        version, off = varint.decode(prefix, 0)
        codec, off = varint.decode(prefix, off)
        hcode, off = varint.decode(prefix, off)
        hlen, off = varint.decode(prefix, off)
        mh = multihash.digest(data, hcode)
        _, d = multihash.decode(mh)
        if hlen != len(d):
            mh = multihash.wrap(hcode, d[:hlen])
        return cls(version, codec, mh)

    def verify(self, data: bytes) -> bool:
        return multihash.verify(self.multihash, data)
