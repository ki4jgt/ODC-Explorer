"""multistream-select 1.0.0 protocol negotiation."""

from .. import varint

PROTOCOL_ID = "/multistream/1.0.0"
NA = "na"
MAX_MSG = 1024


class NegotiationError(Exception):
    pass


def encode_msg(msg: str) -> bytes:
    b = msg.encode() + b"\n"
    return varint.encode(len(b)) + b


def read_msg(conn) -> str:
    n = varint.read(conn.read_exact)
    if n > MAX_MSG:
        raise NegotiationError("multistream message too large")
    b = conn.read_exact(n)
    if not b.endswith(b"\n"):
        raise NegotiationError("multistream message missing newline")
    return b[:-1].decode()


def select(conn, protocols) -> str:
    """Dialer side: propose ``protocols`` in order; return the accepted one.
    ``conn`` needs ``write(bytes)`` and ``read_exact(n)``."""
    if isinstance(protocols, str):
        protocols = [protocols]
    conn.write(encode_msg(PROTOCOL_ID) + encode_msg(protocols[0]))
    if read_msg(conn) != PROTOCOL_ID:
        raise NegotiationError("peer does not speak multistream 1.0.0")
    for i, proto in enumerate(protocols):
        if i:
            conn.write(encode_msg(proto))
        resp = read_msg(conn)
        if resp == proto:
            return proto
        if resp != NA:
            raise NegotiationError(f"unexpected multistream response {resp!r}")
    raise NegotiationError(f"peer supports none of {protocols}")


def handle(conn, supported) -> str:
    """Listener side: respond to proposals; return the agreed protocol.
    ``supported`` is a container (or callable) of acceptable protocol IDs."""
    accept = supported if callable(supported) else (lambda p: p in supported)
    conn.write(encode_msg(PROTOCOL_ID))
    if read_msg(conn) != PROTOCOL_ID:
        raise NegotiationError("peer does not speak multistream 1.0.0")
    while True:
        proto = read_msg(conn)
        if proto == "ls":
            listing = b"".join(encode_msg(p) for p in (supported if not callable(supported) else []))
            conn.write(varint.encode(len(listing) + 1) + listing + b"\n")
        elif accept(proto):
            conn.write(encode_msg(proto))
            return proto
        else:
            conn.write(encode_msg(NA))
