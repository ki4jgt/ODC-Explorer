"""Unsigned LEB128 varints, as used throughout multiformats and libp2p."""

MAX_LEN = 9  # multiformats caps varints at 9 bytes (63 bits)


def encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode(buf, offset: int = 0):
    """Decode a varint from ``buf`` at ``offset``. Returns ``(value, new_offset)``."""
    value = shift = 0
    for i in range(MAX_LEN):
        if offset + i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[offset + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            if i > 0 and b == 0:
                raise ValueError("varint not minimally encoded")
            return value, offset + i + 1
        shift += 7
    raise ValueError("varint too long")


def read(read_exact) -> int:
    """Read a varint using ``read_exact(n) -> bytes``."""
    value = shift = 0
    for i in range(MAX_LEN):
        b = read_exact(1)
        if not b:
            raise EOFError("EOF while reading varint")
        b = b[0]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value
        shift += 7
    raise ValueError("varint too long")
