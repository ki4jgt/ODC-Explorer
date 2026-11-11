"""DAG-CBOR codec: deterministic CBOR with CIDs as tag 42.

Python mapping: dict (str keys), list, str, bytes, int, float, bool, None, CID.
"""

import struct

from .cid import CID


def encode(obj) -> bytes:
    out = bytearray()
    _enc(obj, out)
    return bytes(out)


def _head(major, n, out):
    if n < 24:
        out.append(major << 5 | n)
    elif n < 0x100:
        out += bytes([major << 5 | 24, n])
    elif n < 0x10000:
        out.append(major << 5 | 25)
        out += struct.pack(">H", n)
    elif n < 0x100000000:
        out.append(major << 5 | 26)
        out += struct.pack(">I", n)
    elif n < 0x10000000000000000:
        out.append(major << 5 | 27)
        out += struct.pack(">Q", n)
    else:
        raise ValueError("integer too large for DAG-CBOR")


def _enc(o, out):
    if o is None:
        out.append(0xF6)
    elif o is True:
        out.append(0xF5)
    elif o is False:
        out.append(0xF4)
    elif isinstance(o, int):
        if o >= 0:
            _head(0, o, out)
        else:
            _head(1, -1 - o, out)
    elif isinstance(o, float):
        if o != o or o in (float("inf"), float("-inf")):
            raise ValueError("DAG-CBOR forbids NaN/Infinity")
        out.append(0xFB)
        out += struct.pack(">d", o)
    elif isinstance(o, (bytes, bytearray, memoryview)):
        _head(2, len(o), out)
        out += bytes(o)
    elif isinstance(o, str):
        b = o.encode("utf-8")
        _head(3, len(b), out)
        out += b
    elif isinstance(o, CID):
        out += b"\xd8\x2a"
        b = b"\x00" + o.to_bytes()
        _head(2, len(b), out)
        out += b
    elif isinstance(o, (list, tuple)):
        _head(4, len(o), out)
        for v in o:
            _enc(v, out)
    elif isinstance(o, dict):
        keys = []
        for k in o:
            if not isinstance(k, str):
                raise TypeError("DAG-CBOR map keys must be strings")
            keys.append((k.encode("utf-8"), k))
        keys.sort(key=lambda kb: (len(kb[0]), kb[0]))
        _head(5, len(keys), out)
        for kb, k in keys:
            _head(3, len(kb), out)
            out += kb
            _enc(o[k], out)
    else:
        raise TypeError(f"cannot DAG-CBOR encode {type(o).__name__}")


def decode(buf: bytes):
    buf = bytes(buf)
    v, off = _dec(buf, 0)
    if off != len(buf):
        raise ValueError("trailing bytes after DAG-CBOR value")
    return v


def _arg(buf, off, info):
    if info < 24:
        return info, off
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None:
        raise ValueError("indefinite lengths are not allowed in DAG-CBOR")
    if off + size > len(buf):
        raise ValueError("truncated CBOR")
    return int.from_bytes(buf[off:off + size], "big"), off + size


def _dec(buf, off):
    if off >= len(buf):
        raise ValueError("truncated CBOR")
    ib = buf[off]
    off += 1
    major, info = ib >> 5, ib & 31
    if major == 7:
        if info == 20:
            return False, off
        if info == 21:
            return True, off
        if info == 22:
            return None, off
        if info == 25:
            return _half(buf[off:off + 2]), off + 2
        if info == 26:
            return struct.unpack(">f", buf[off:off + 4])[0], off + 4
        if info == 27:
            return struct.unpack(">d", buf[off:off + 8])[0], off + 8
        raise ValueError(f"unsupported CBOR simple value {info}")
    n, off = _arg(buf, off, info)
    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major in (2, 3):
        if off + n > len(buf):
            raise ValueError("truncated CBOR")
        b = buf[off:off + n]
        return (b if major == 2 else b.decode("utf-8")), off + n
    if major == 4:
        items = []
        for _ in range(n):
            v, off = _dec(buf, off)
            items.append(v)
        return items, off
    if major == 5:
        d = {}
        for _ in range(n):
            k, off = _dec(buf, off)
            if not isinstance(k, str):
                raise ValueError("DAG-CBOR map keys must be strings")
            d[k], off = _dec(buf, off)
        return d, off
    if major == 6:
        v, off = _dec(buf, off)
        if n != 42:
            raise ValueError(f"unsupported CBOR tag {n}")
        if not isinstance(v, bytes) or not v or v[0] != 0:
            raise ValueError("invalid CID in tag 42")
        return CID.from_bytes(v[1:]), off
    raise ValueError("bad CBOR")


def _half(b):
    h = int.from_bytes(b, "big")
    s, e, f = h >> 15, (h >> 10) & 0x1F, h & 0x3FF
    if e == 0:
        v = f * 2.0 ** -24
    elif e == 31:
        v = float("inf") if f == 0 else float("nan")
    else:
        v = (1 + f / 1024) * 2.0 ** (e - 15)
    return -v if s else v


def links(obj):
    """Return all CIDs referenced inside a decoded DAG-CBOR value."""
    out = []
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, CID):
            out.append(o)
        elif isinstance(o, dict):
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)
    return out
