"""A tiny protocol-buffers wire-format encoder/decoder.

Messages are decoded into ``{field_number: [values...]}``. Varints come back as
ints, length-delimited fields as ``bytes``, fixed32/fixed64 as ints. Callers
interpret the raw values according to their schema.
"""

import struct

from . import varint

VARINT, I64, LEN, I32 = 0, 1, 2, 5


def key(field: int, wire: int) -> bytes:
    return varint.encode((field << 3) | wire)


def enc_varint(field: int, value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1  # two's complement for int32/int64
    return key(field, VARINT) + varint.encode(value)


def enc_bytes(field: int, value) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    return key(field, LEN) + varint.encode(len(value)) + bytes(value)


def enc_fixed32(field: int, value: int) -> bytes:
    return key(field, I32) + struct.pack("<I", value)


def enc_fixed64(field: int, value: int) -> bytes:
    return key(field, I64) + struct.pack("<Q", value)


def decode(buf) -> dict:
    buf = bytes(buf)
    out = {}
    off = 0
    n = len(buf)
    while off < n:
        k, off = _varint_any(buf, off)
        field, wire = k >> 3, k & 7
        if wire == VARINT:
            v, off = _varint_any(buf, off)
        elif wire == LEN:
            ln, off = _varint_any(buf, off)
            if off + ln > n:
                raise ValueError("truncated protobuf field")
            v = buf[off:off + ln]
            off += ln
        elif wire == I32:
            v = struct.unpack_from("<I", buf, off)[0]
            off += 4
        elif wire == I64:
            v = struct.unpack_from("<Q", buf, off)[0]
            off += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
        out.setdefault(field, []).append(v)
    return out


def _varint_any(buf, off):
    # protobuf varints may be up to 10 bytes and need not be minimal
    value = shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated varint")
        b = buf[off]
        off += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, off
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def first(msg: dict, field: int, default=None):
    v = msg.get(field)
    return v[0] if v else default


def to_signed(v: int, bits: int = 64) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v
