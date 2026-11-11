"""DAG-PB codec (MerkleDAG protobuf nodes)."""

from . import protobuf as pb
from .cid import CID


class PBLink:
    __slots__ = ("cid", "name", "tsize")

    def __init__(self, cid, name=None, tsize=None):
        self.cid = CID.decode(cid)
        self.name = name
        self.tsize = tsize

    def encode(self) -> bytes:
        out = pb.enc_bytes(1, self.cid.to_bytes())
        if self.name is not None:
            out += pb.enc_bytes(2, self.name.encode("utf-8"))
        if self.tsize is not None:
            out += pb.enc_varint(3, self.tsize)
        return out

    def __repr__(self):
        return f"PBLink({self.cid}, name={self.name!r}, tsize={self.tsize})"


class PBNode:
    __slots__ = ("links", "data")

    def __init__(self, links=None, data=None):
        self.links = list(links or [])
        self.data = data

    def encode(self) -> bytes:
        # DAG-PB canonical form: Links (field 2) are written before Data (field 1)
        out = b"".join(pb.enc_bytes(2, l.encode()) for l in self.links)
        if self.data is not None:
            out += pb.enc_bytes(1, self.data)
        return out

    @classmethod
    def decode(cls, buf: bytes) -> "PBNode":
        msg = pb.decode(buf)
        links = []
        for raw in msg.get(2, []):
            lm = pb.decode(raw)
            name = pb.first(lm, 2)
            links.append(PBLink(CID.from_bytes(pb.first(lm, 1)),
                                name.decode("utf-8") if name is not None else None,
                                pb.first(lm, 3)))
        return cls(links, pb.first(msg, 1))

    def __repr__(self):
        return f"PBNode(links={len(self.links)}, data={len(self.data or b'')}B)"


def encode(node: PBNode) -> bytes:
    return node.encode()


def decode(buf: bytes) -> PBNode:
    return PBNode.decode(buf)
