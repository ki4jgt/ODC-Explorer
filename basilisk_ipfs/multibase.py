"""Multibase: self-describing base encodings."""

import base64

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def _base_x_encode(data: bytes, alphabet: str) -> str:
    base = len(alphabet)
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, base)
        out.append(alphabet[r])
    pad = len(data) - len(data.lstrip(b"\0"))
    return alphabet[0] * pad + "".join(reversed(out))


def _base_x_decode(s: str, alphabet: str) -> bytes:
    base = len(alphabet)
    n = 0
    for ch in s:
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError(f"invalid character {ch!r}")
        n = n * base + idx
    pad = len(s) - len(s.lstrip(alphabet[0]))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * pad + body


def b58encode(data: bytes) -> str:
    return _base_x_encode(data, B58_ALPHABET)


def b58decode(s: str) -> bytes:
    return _base_x_decode(s, B58_ALPHABET)


def _b32_decode(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _b64_decode(s: str, urlsafe: bool) -> bytes:
    s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s) if urlsafe else base64.b64decode(s)


# prefix -> (name, encoder, decoder)
_CODECS = {
    "f": ("base16", lambda b: b.hex(), bytes.fromhex),
    "F": ("base16upper", lambda b: b.hex().upper(), bytes.fromhex),
    "b": ("base32", lambda b: base64.b32encode(b).decode().rstrip("=").lower(), _b32_decode),
    "B": ("base32upper", lambda b: base64.b32encode(b).decode().rstrip("="), _b32_decode),
    "c": ("base32pad", lambda b: base64.b32encode(b).decode().lower(), _b32_decode),
    "C": ("base32padupper", lambda b: base64.b32encode(b).decode(), _b32_decode),
    "k": ("base36", lambda b: _base_x_encode(b, B36_ALPHABET), lambda s: _base_x_decode(s, B36_ALPHABET)),
    "K": ("base36upper", lambda b: _base_x_encode(b, B36_ALPHABET).upper(),
          lambda s: _base_x_decode(s.lower(), B36_ALPHABET)),
    "z": ("base58btc", b58encode, b58decode),
    "m": ("base64", lambda b: base64.b64encode(b).decode().rstrip("="), lambda s: _b64_decode(s, False)),
    "M": ("base64pad", lambda b: base64.b64encode(b).decode(), lambda s: _b64_decode(s, False)),
    "u": ("base64url", lambda b: base64.urlsafe_b64encode(b).decode().rstrip("="), lambda s: _b64_decode(s, True)),
    "U": ("base64urlpad", lambda b: base64.urlsafe_b64encode(b).decode(), lambda s: _b64_decode(s, True)),
}
_BY_NAME = {v[0]: k for k, v in _CODECS.items()}


def encode(data: bytes, base: str = "base32") -> str:
    prefix = _BY_NAME.get(base)
    if prefix is None:
        raise ValueError(f"unsupported multibase {base!r}")
    return prefix + _CODECS[prefix][1](bytes(data))


def decode(s: str) -> bytes:
    return decode_with_base(s)[1]


def decode_with_base(s: str):
    """Return ``(base_name, data)``."""
    if not s:
        raise ValueError("empty multibase string")
    codec = _CODECS.get(s[0])
    if codec is None:
        raise ValueError(f"unsupported multibase prefix {s[0]!r}")
    return codec[0], codec[2](s[1:])


def names():
    return list(_BY_NAME)
