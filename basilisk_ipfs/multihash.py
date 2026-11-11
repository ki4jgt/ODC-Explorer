"""Multihash: self-describing hash digests."""

import hashlib

from . import varint
from .multicodec import code as _code, name as _name

_HASHERS = {
    0x00: lambda d: bytes(d),
    0x11: lambda d: hashlib.sha1(d).digest(),
    0x12: lambda d: hashlib.sha256(d).digest(),
    0x13: lambda d: hashlib.sha512(d).digest(),
    0x14: lambda d: hashlib.sha3_512(d).digest(),
    0x15: lambda d: hashlib.sha3_384(d).digest(),
    0x16: lambda d: hashlib.sha3_256(d).digest(),
    0x17: lambda d: hashlib.sha3_224(d).digest(),
    0xB220: lambda d: hashlib.blake2b(d, digest_size=32).digest(),
    0xB240: lambda d: hashlib.blake2b(d, digest_size=64).digest(),
    0xB260: lambda d: hashlib.blake2s(d, digest_size=32).digest(),
}


def digest(data: bytes, fn="sha2-256") -> bytes:
    """Hash ``data`` and return the encoded multihash."""
    c = _code(fn)
    if c not in _HASHERS:
        raise ValueError(f"unsupported hash function {fn!r}")
    d = _HASHERS[c](data)
    return varint.encode(c) + varint.encode(len(d)) + d


def wrap(fn, raw_digest: bytes) -> bytes:
    return varint.encode(_code(fn)) + varint.encode(len(raw_digest)) + raw_digest


def decode(mh: bytes):
    """Return ``(code, digest)`` for an encoded multihash; validates length."""
    c, off = varint.decode(mh, 0)
    ln, off = varint.decode(mh, off)
    d = mh[off:]
    if len(d) != ln:
        raise ValueError("multihash length mismatch")
    return c, bytes(d)


def read(buf: bytes, offset: int = 0):
    """Parse a multihash at ``offset`` inside ``buf``; return ``(mh_bytes, new_offset)``."""
    _, off = varint.decode(buf, offset)
    ln, off = varint.decode(buf, off)
    end = off + ln
    if end > len(buf):
        raise ValueError("truncated multihash")
    return bytes(buf[offset:end]), end


def verify(mh: bytes, data: bytes) -> bool:
    c, d = decode(mh)
    if c not in _HASHERS:
        raise ValueError(f"unsupported hash function {_name(c)}")
    return _HASHERS[c](data)[: len(d)] == d


def supported(fn) -> bool:
    return _code(fn) in _HASHERS
