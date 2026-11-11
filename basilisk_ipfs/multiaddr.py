"""Multiaddr: self-describing network addresses (string and binary forms)."""

import ipaddress
import struct

from . import multibase, varint

# code -> (name, size) ; size: bits (>0), 0 = no value, -1 = varint-length-prefixed
PROTOCOLS = [
    (4, "ip4", 32), (6, "tcp", 16), (273, "udp", 16), (33, "dccp", 16),
    (41, "ip6", 128), (42, "ip6zone", -1), (43, "ipcidr", 8),
    (53, "dns", -1), (54, "dns4", -1), (55, "dns6", -1), (56, "dnsaddr", -1),
    (132, "sctp", 16), (301, "udt", 0), (302, "utp", 0), (400, "unix", -1),
    (421, "p2p", -1), (444, "onion", 96), (445, "onion3", 296), (446, "garlic64", -1),
    (447, "garlic32", -1), (448, "tls", 0), (449, "sni", -1), (454, "noise", 0),
    (460, "quic", 0), (461, "quic-v1", 0), (465, "webtransport", 0),
    (466, "certhash", -1), (477, "ws", 0), (478, "wss", 0),
    (479, "p2p-websocket-star", 0), (275, "p2p-webrtc-star", 0),
    (276, "p2p-webrtc-direct", 0), (280, "webrtc-direct", 0), (281, "webrtc", 0),
    (290, "p2p-circuit", 0), (480, "http", 0), (481, "https", 0),
    (777, "memory", 64),
]
BY_NAME = {n: (c, n, s) for c, n, s in PROTOCOLS}
BY_CODE = {c: (c, n, s) for c, n, s in PROTOCOLS}
BY_NAME["ipfs"] = BY_NAME["p2p"]


def _val_to_bytes(name, value: str) -> bytes:
    if name == "ip4":
        return ipaddress.IPv4Address(value).packed
    if name == "ip6":
        return ipaddress.IPv6Address(value).packed
    if name in ("tcp", "udp", "dccp", "sctp"):
        return struct.pack(">H", int(value))
    if name == "p2p":
        from .keys import PeerID
        return PeerID.decode(value).to_bytes()
    if name == "certhash":
        return multibase.decode(value)
    if name == "ipcidr":
        return bytes([int(value)])
    if name == "memory":
        return struct.pack(">Q", int(value))
    return value.encode()


def _val_to_str(name, b: bytes) -> str:
    if name == "ip4":
        return str(ipaddress.IPv4Address(b))
    if name == "ip6":
        return str(ipaddress.IPv6Address(b))
    if name in ("tcp", "udp", "dccp", "sctp"):
        return str(struct.unpack(">H", b)[0])
    if name == "p2p":
        return multibase.b58encode(b)
    if name == "certhash":
        return multibase.encode(b, "base64url")
    if name == "ipcidr":
        return str(b[0])
    if name == "memory":
        return str(struct.unpack(">Q", b)[0])
    return b.decode()


class Multiaddr:
    __slots__ = ("parts",)  # list of (name, value_str_or_None)

    def __init__(self, addr=None):
        if isinstance(addr, Multiaddr):
            self.parts = list(addr.parts)
        elif isinstance(addr, (bytes, bytearray)):
            self.parts = self._parse_bytes(bytes(addr))
        elif isinstance(addr, str):
            self.parts = self._parse_str(addr)
        elif addr is None:
            self.parts = []
        else:
            self.parts = list(addr)

    @staticmethod
    def _parse_str(s):
        if not s.startswith("/"):
            raise ValueError(f"multiaddr must start with '/': {s!r}")
        toks = s.split("/")[1:]
        if toks and toks[-1] == "":
            toks.pop()
        parts = []
        i = 0
        while i < len(toks):
            name = toks[i]
            if name not in BY_NAME:
                raise ValueError(f"unknown multiaddr protocol {name!r}")
            _, cname, size = BY_NAME[name]
            i += 1
            if size == 0:
                parts.append((cname, None))
                continue
            if cname == "unix":  # path consumes the rest
                parts.append((cname, "/" + "/".join(toks[i:])))
                break
            if i >= len(toks):
                raise ValueError(f"missing value for {name}")
            _val_to_bytes(cname, toks[i])  # validate
            parts.append((cname, toks[i]))
            i += 1
        return parts

    @staticmethod
    def _parse_bytes(b):
        parts, off = [], 0
        while off < len(b):
            code, off = varint.decode(b, off)
            if code not in BY_CODE:
                raise ValueError(f"unknown multiaddr code {code}")
            _, name, size = BY_CODE[code]
            if size == 0:
                parts.append((name, None))
                continue
            if size < 0:
                ln, off = varint.decode(b, off)
            else:
                ln = size // 8
            if off + ln > len(b):
                raise ValueError("truncated multiaddr")
            parts.append((name, _val_to_str(name, b[off:off + ln])))
            off += ln
        return parts

    def to_bytes(self) -> bytes:
        out = bytearray()
        for name, value in self.parts:
            code, _, size = BY_NAME[name]
            out += varint.encode(code)
            if size == 0:
                continue
            vb = _val_to_bytes(name, value)
            if size < 0:
                out += varint.encode(len(vb))
            out += vb
        return bytes(out)

    __bytes__ = to_bytes

    def __str__(self):
        return "".join(f"/{n}" if v is None else f"/{n}/{v}" for n, v in self.parts)

    def __repr__(self):
        return f"Multiaddr({str(self)!r})"

    def __eq__(self, other):
        return isinstance(other, Multiaddr) and self.parts == other.parts

    def __hash__(self):
        return hash(str(self))

    def value_for(self, name):
        for n, v in self.parts:
            if n == name:
                return v
        return None

    def protocols(self):
        return [n for n, _ in self.parts]

    def encapsulate(self, other) -> "Multiaddr":
        return Multiaddr(self.parts + Multiaddr(other).parts)

    def decapsulate_p2p(self):
        """Split off a trailing /p2p/<id>. Returns (addr_without_p2p, PeerID|None)."""
        from .keys import PeerID
        if self.parts and self.parts[-1][0] == "p2p":
            return Multiaddr(self.parts[:-1]), PeerID.decode(self.parts[-1][1])
        return self, None

    @property
    def peer_id(self):
        return self.decapsulate_p2p()[1]

    def tcp_target(self):
        """Return (host, port) if this is a plain TCP address we can dial, else None."""
        protos = self.decapsulate_p2p()[0].protocols()
        if len(protos) != 2 or protos[1] != "tcp" or protos[0] not in ("ip4", "ip6", "dns", "dns4", "dns6"):
            return None
        return self.parts[0][1], int(self.parts[1][1])
