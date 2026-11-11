"""UnixFS v1: files, directories, symlinks and HAMT-sharded directories on top
of DAG-PB.

The importer reproduces Kubo's defaults (fixed 256 KiB chunks, balanced DAG
with 174 links per node, CIDv0 / dag-pb leaves, or CIDv1 / raw leaves), so the
CIDs produced are identical to ``ipfs add``.

Exporter functions take a ``blocks`` object exposing ``get(cid) -> bytes``
(a Blockstore, or a network fetcher). If it also exposes
``get_many(cids) -> dict[CID, bytes]`` that is used to fetch siblings in
parallel.
"""

import io
import os
import stat as _stat

from . import protobuf as pb
from .cid import CID
from .dagpb import PBLink, PBNode

RAW, DIRECTORY, FILE, METADATA, SYMLINK, HAMT_SHARD = 0, 1, 2, 3, 4, 5
TYPE_NAMES = {0: "raw", 1: "directory", 2: "file", 3: "metadata", 4: "symlink", 5: "hamt-shard"}

DEFAULT_CHUNK_SIZE = 256 * 1024
DEFAULT_MAX_LINKS = 174
HAMT_FANOUT = 256
HAMT_THRESHOLD = 256 * 1024
MURMUR3_X64_64 = 0x22


# --------------------------------------------------------------------------
# UnixFS Data message
# --------------------------------------------------------------------------
class Data:
    __slots__ = ("type", "data", "filesize", "blocksizes", "hash_type", "fanout", "mode", "mtime")

    def __init__(self, type=FILE, data=None, filesize=None, blocksizes=None,
                 hash_type=None, fanout=None, mode=None, mtime=None):
        self.type = type
        self.data = data
        self.filesize = filesize
        self.blocksizes = list(blocksizes or [])
        self.hash_type = hash_type
        self.fanout = fanout
        self.mode = mode
        self.mtime = mtime  # (seconds, nanos) or None

    def encode(self) -> bytes:
        out = pb.enc_varint(1, self.type)
        if self.data is not None:
            out += pb.enc_bytes(2, self.data)
        if self.filesize is not None:
            out += pb.enc_varint(3, self.filesize)
        for bs in self.blocksizes:
            out += pb.enc_varint(4, bs)
        if self.hash_type is not None:
            out += pb.enc_varint(5, self.hash_type)
        if self.fanout is not None:
            out += pb.enc_varint(6, self.fanout)
        if self.mode is not None:
            out += pb.enc_varint(7, self.mode)
        if self.mtime is not None:
            t = pb.enc_varint(1, self.mtime[0])
            if self.mtime[1]:
                t += pb.enc_fixed32(2, self.mtime[1])
            out += pb.enc_bytes(8, t)
        return out

    @classmethod
    def decode(cls, buf: bytes) -> "Data":
        m = pb.decode(buf)
        mtime = None
        if 8 in m:
            t = pb.decode(m[8][0])
            mtime = (pb.to_signed(pb.first(t, 1, 0)), pb.first(t, 2, 0))
        return cls(pb.first(m, 1, FILE), pb.first(m, 2), pb.first(m, 3), m.get(4, []),
                   pb.first(m, 5), pb.first(m, 6), pb.first(m, 7), mtime)

    def file_size(self) -> int:
        if self.filesize is not None:
            return self.filesize
        return len(self.data or b"") + sum(self.blocksizes)

    def __repr__(self):
        return f"UnixFSData(type={TYPE_NAMES.get(self.type, self.type)}, size={self.file_size()})"


# --------------------------------------------------------------------------
# Importer
# --------------------------------------------------------------------------
class ImportResult:
    """The root of an imported DAG."""
    __slots__ = ("cid", "size", "cumulative_size", "name")

    def __init__(self, cid, size, cumulative_size, name=""):
        self.cid, self.size, self.cumulative_size, self.name = cid, size, cumulative_size, name

    def __repr__(self):
        return f"ImportResult({self.name!r}, {self.cid}, size={self.size})"


class Importer:
    """Builds UnixFS DAGs into a blockstore.

    ``cid_version=0`` (Kubo default) produces dag-pb leaves and CIDv0.
    ``cid_version=1`` implies raw leaves unless ``raw_leaves`` is given.
    """

    def __init__(self, blockstore, chunk_size=DEFAULT_CHUNK_SIZE, cid_version=0,
                 raw_leaves=None, hash_fn="sha2-256", max_links=DEFAULT_MAX_LINKS,
                 hamt_threshold=HAMT_THRESHOLD, include_hidden=False):
        if cid_version == 0 and hash_fn != "sha2-256":
            cid_version = 1
        self.store = blockstore
        self.chunk_size = chunk_size
        self.cid_version = cid_version
        self.raw_leaves = (cid_version == 1) if raw_leaves is None else raw_leaves
        self.hash_fn = hash_fn
        self.max_links = max_links
        self.hamt_threshold = hamt_threshold
        self.include_hidden = include_hidden

    # -- primitives --
    def _put_node(self, node: PBNode):
        raw = node.encode()
        cid = CID.from_data(raw, "dag-pb", self.cid_version, self.hash_fn)
        self.store.put(cid, raw, verify=False)
        cum = len(raw) + sum(l.tsize or 0 for l in node.links)
        return cid, cum

    def _leaf(self, chunk: bytes):
        """Returns (cid, file_bytes, cumulative_size)."""
        if self.raw_leaves:
            cid = CID.from_data(chunk, "raw", 1, self.hash_fn)
            self.store.put(cid, chunk, verify=False)
            return cid, len(chunk), len(chunk)
        d = Data(FILE, chunk if chunk else None, len(chunk))
        cid, cum = self._put_node(PBNode([], d.encode()))
        return cid, len(chunk), cum

    def _chunks(self, stream):
        while True:
            buf = bytearray()
            while len(buf) < self.chunk_size:
                part = stream.read(self.chunk_size - len(buf))
                if not part:
                    break
                buf += part
            if not buf:
                return
            yield bytes(buf)
            if len(buf) < self.chunk_size:
                return

    # -- files --
    def add_bytes(self, data: bytes, name="") -> ImportResult:
        return self.add_stream(io.BytesIO(data), name)

    def add_stream(self, stream, name="") -> ImportResult:
        chunks = self._chunks(stream)
        first = next(chunks, None)
        if first is None:
            cid, size, cum = self._leaf(b"")
            return ImportResult(cid, 0, cum, name)

        pending = [first]

        def next_leaf():
            c = pending.pop() if pending else next(chunks, None)
            return None if c is None else self._leaf(c)

        def peek_done():
            if pending:
                return False
            c = next(chunks, None)
            if c is None:
                return True
            pending.append(c)
            return False

        # balanced layout, as in go-unixfs importer/balanced
        root = next_leaf()  # (cid, filesize, cumulative)
        depth = 1
        while not peek_done():
            links = [root]
            root = self._fill(links, depth, next_leaf, peek_done)
            depth += 1
        cid, size, cum = root
        return ImportResult(cid, size, cum, name)

    def _fill(self, children, depth, next_leaf, peek_done):
        while len(children) < self.max_links and not peek_done():
            if depth == 1:
                children.append(next_leaf())
            else:
                children.append(self._fill([], depth - 1, next_leaf, peek_done))
        sizes = [c[1] for c in children]
        d = Data(FILE, None, sum(sizes), sizes)
        node = PBNode([PBLink(c[0], "", c[2]) for c in children], d.encode())
        cid, cum = self._put_node(node)
        return cid, sum(sizes), cum

    def add_file(self, path, name=None) -> ImportResult:
        with open(path, "rb") as f:
            return self.add_stream(f, os.path.basename(path) if name is None else name)

    def add_symlink(self, target: str, name="") -> ImportResult:
        d = Data(SYMLINK, target.encode())
        cid, cum = self._put_node(PBNode([], d.encode()))
        return ImportResult(cid, 0, cum, name)

    # -- directories --
    def add_directory_entries(self, entries, name="") -> ImportResult:
        """Build a directory from ``ImportResult``-like entries (name, cid, cumulative_size)."""
        entries = sorted(entries, key=lambda e: e.name.encode("utf-8"))
        names = [e.name for e in entries]
        if len(set(names)) != len(names):
            raise ValueError("duplicate directory entry names")
        est = sum(len(e.name.encode()) + len(e.cid.to_bytes()) for e in entries)
        if self.hamt_threshold and est >= self.hamt_threshold:
            cid, cum = self._hamt(entries, 0)
        else:
            node = PBNode([PBLink(e.cid, e.name, e.cumulative_size) for e in entries],
                          Data(DIRECTORY).encode())
            cid, cum = self._put_node(node)
        total = sum(e.size for e in entries)
        return ImportResult(cid, total, cum, name)

    def _hamt(self, entries, depth):
        width = len(f"{HAMT_FANOUT - 1:X}")
        buckets = {}
        for e in entries:
            h = _hamt_hash(e.name.encode())
            if depth >= len(h):
                raise ValueError("HAMT hash exhausted")
            buckets.setdefault(h[depth], []).append(e)
        links = []
        bitfield = 0
        for idx in sorted(buckets):
            bitfield |= 1 << idx
            prefix = f"{idx:0{width}X}"
            group = buckets[idx]
            if len(group) == 1:
                e = group[0]
                links.append(PBLink(e.cid, prefix + e.name, e.cumulative_size))
            else:
                cid, cum = self._hamt(group, depth + 1)
                links.append(PBLink(cid, prefix, cum))
        bf = bitfield.to_bytes((bitfield.bit_length() + 7) // 8, "big")
        d = Data(HAMT_SHARD, bf, hash_type=MURMUR3_X64_64, fanout=HAMT_FANOUT)
        return self._put_node(PBNode(links, d.encode()))

    def add_path(self, path, name=None) -> ImportResult:
        """Recursively import a file, symlink, or directory from disk."""
        name = os.path.basename(os.path.normpath(path)) if name is None else name
        st = os.lstat(path)
        if _stat.S_ISLNK(st.st_mode):
            return self.add_symlink(os.readlink(path), name)
        if _stat.S_ISDIR(st.st_mode):
            children = []
            for child in sorted(os.listdir(path)):
                if not self.include_hidden and child.startswith("."):
                    continue
                children.append(self.add_path(os.path.join(path, child), child))
            return self.add_directory_entries(children, name)
        return self.add_file(path, name)

    def wrap(self, results, name="") -> ImportResult:
        """Wrap one or more results in a directory (``ipfs add -w``)."""
        return self.add_directory_entries(list(results), name)


# --------------------------------------------------------------------------
# murmur3 (x64, 128-bit; first 64 bits) for HAMT
# --------------------------------------------------------------------------
_M64 = (1 << 64) - 1


def _rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & _M64


def _fmix(k):
    k ^= k >> 33
    k = (k * 0xFF51AFD7ED558CCD) & _M64
    k ^= k >> 33
    k = (k * 0xC4CEB9FE1A85EC53) & _M64
    return k ^ (k >> 33)


def murmur3_x64_128(data: bytes, seed: int = 0):
    c1, c2 = 0x87C37B91114253D5, 0x4CF5AD432745937F
    h1 = h2 = seed
    n = len(data) // 16
    for i in range(n):
        k1 = int.from_bytes(data[16 * i:16 * i + 8], "little")
        k2 = int.from_bytes(data[16 * i + 8:16 * i + 16], "little")
        k1 = _rotl((k1 * c1) & _M64, 31) * c2 & _M64
        h1 ^= k1
        h1 = (_rotl(h1, 27) + h2) & _M64
        h1 = (h1 * 5 + 0x52DCE729) & _M64
        k2 = _rotl((k2 * c2) & _M64, 33) * c1 & _M64
        h2 ^= k2
        h2 = (_rotl(h2, 31) + h1) & _M64
        h2 = (h2 * 5 + 0x38495AB5) & _M64
    tail = data[16 * n:]
    if len(tail) > 8:
        k2 = int.from_bytes(tail[8:], "little")
        h2 ^= _rotl((k2 * c2) & _M64, 33) * c1 & _M64
    if tail:
        k1 = int.from_bytes(tail[:8], "little")
        h1 ^= _rotl((k1 * c1) & _M64, 31) * c2 & _M64
    h1 ^= len(data)
    h2 ^= len(data)
    h1 = (h1 + h2) & _M64
    h2 = (h2 + h1) & _M64
    h1, h2 = _fmix(h1), _fmix(h2)
    h1 = (h1 + h2) & _M64
    h2 = (h2 + h1) & _M64
    return h1, h2


def _hamt_hash(name: bytes) -> bytes:
    return murmur3_x64_128(name)[0].to_bytes(8, "big")


# --------------------------------------------------------------------------
# Exporter
# --------------------------------------------------------------------------
def _get_many(blocks, cids):
    if hasattr(blocks, "get_many"):
        got = blocks.get_many(cids)
        return [got[c] for c in cids]
    return [blocks.get(c) for c in cids]


def load(blocks, cid):
    """Returns ``(cid, PBNode or None, Data or None, raw_bytes)``."""
    cid = CID.decode(cid)
    raw = blocks.get(cid)
    return _parse(cid, raw)


def _parse(cid, raw):
    if cid.codec == 0x55:
        return cid, None, None, raw
    if cid.codec != 0x70:
        raise ValueError(f"not a UnixFS node: codec {cid.codec_name}")
    node = PBNode.decode(raw)
    data = Data.decode(node.data) if node.data is not None else None
    return cid, node, data, raw


def stat(blocks, cid) -> dict:
    cid, node, data, raw = load(blocks, cid)
    if node is None:
        return {"cid": cid, "type": "file", "size": len(raw), "blocks": 0,
                "cumulative_size": len(raw)}
    cum = len(raw) + sum(l.tsize or 0 for l in node.links)
    t = TYPE_NAMES.get(data.type, "unknown") if data else "unknown"
    size = data.file_size() if data and data.type in (FILE, RAW) else (
        len(data.data or b"") if data and data.type == SYMLINK else 0)
    if t == "hamt-shard":
        t = "directory"
    out = {"cid": cid, "type": t, "size": size, "blocks": len(node.links), "cumulative_size": cum}
    if data and data.mode is not None:
        out["mode"] = data.mode
    if data and data.mtime is not None:
        out["mtime"] = data.mtime
    return out


def cat(blocks, cid, offset: int = 0, length: int = None):
    """Yield the bytes of a UnixFS file (or raw block), optionally a byte range."""
    end = None if length is None else offset + length
    cid, node, data, raw = load(blocks, cid)
    yield from _cat(blocks, cid, node, data, raw, offset, end)


def _cat(blocks, cid, node, data, raw, start, end):
    if node is None:  # raw leaf
        if end is not None and end <= start:
            return
        piece = raw[start:end]
        if piece:
            yield piece
        return
    if data is None or data.type not in (FILE, RAW):
        kind = TYPE_NAMES.get(data.type, "?") if data else "dag-pb without unixfs data"
        raise IsADirectoryError(f"{cid} is a {kind}, not a file")
    pos = 0
    if data.data:
        ln = len(data.data)
        s, e = max(start, 0), ln if end is None else min(end, ln)
        if s < e:
            yield data.data[s:e]
        pos = ln
    # select only the children that overlap the requested range
    wanted = []
    for link, bs in zip(node.links, data.blocksizes):
        cs, ce = pos, pos + bs
        pos = ce
        if ce <= start or (end is not None and cs >= end):
            continue
        wanted.append((link.cid, cs))
    for i in range(0, len(wanted), 32):
        batch = wanted[i:i + 32]
        raws = _get_many(blocks, [c for c, _ in batch])
        for (ccid, cs), craw in zip(batch, raws):
            c, n, d, r = _parse(ccid, craw)
            yield from _cat(blocks, c, n, d, r, max(start - cs, 0),
                            None if end is None else end - cs)


def read(blocks, cid, offset=0, length=None) -> bytes:
    return b"".join(cat(blocks, cid, offset, length))


class Entry:
    __slots__ = ("name", "cid", "size")

    def __init__(self, name, cid, size):
        self.name, self.cid, self.size = name, cid, size

    def __repr__(self):
        return f"Entry({self.name!r}, {self.cid}, {self.size})"


def ls(blocks, cid):
    """List a directory (plain or HAMT-sharded). Returns a list of ``Entry``."""
    cid, node, data, _ = load(blocks, cid)
    if node is None or data is None or data.type not in (DIRECTORY, HAMT_SHARD):
        raise NotADirectoryError(f"{cid} is not a directory")
    if data.type == DIRECTORY:
        return [Entry(l.name, l.cid, l.tsize) for l in node.links]
    return list(_hamt_entries(blocks, node, data))


def _hamt_entries(blocks, node, data):
    width = len(f"{(data.fanout or HAMT_FANOUT) - 1:X}")
    subs = []
    for l in node.links:
        if len(l.name) > width:
            yield Entry(l.name[width:], l.cid, l.tsize)
        else:
            subs.append(l.cid)
    if subs:
        for c, raw in zip(subs, _get_many(blocks, subs)):
            _, n, d, _ = _parse(c, raw)
            yield from _hamt_entries(blocks, n, d)


def _hamt_lookup(blocks, node, data, name: str, depth=0):
    width = len(f"{(data.fanout or HAMT_FANOUT) - 1:X}")
    if data.fanout and data.fanout != 256 or data.hash_type != MURMUR3_X64_64:
        # unusual parameters: fall back to scanning
        for e in _hamt_entries(blocks, node, data):
            if e.name == name:
                return e.cid
        return None
    idx = _hamt_hash(name.encode())[depth]
    prefix = f"{idx:0{width}X}"
    for l in node.links:
        if not l.name.startswith(prefix):
            continue
        if len(l.name) == width:
            _, n, d, _ = load(blocks, l.cid)
            return _hamt_lookup(blocks, n, d, name, depth + 1)
        if l.name[width:] == name:
            return l.cid
    return None


def resolve(blocks, path):
    """Resolve ``/ipfs/<cid>/a/b`` (or ``<cid>/a/b``) to the CID it names."""
    if isinstance(path, CID):
        return path
    parts = [p for p in str(path).split("/") if p]
    if parts and parts[0] == "ipfs":
        parts = parts[1:]
    if not parts:
        raise ValueError("empty path")
    cid = CID.decode(parts[0])
    for name in parts[1:]:
        _, node, data, _ = load(blocks, cid)
        if node is None:
            raise FileNotFoundError(f"cannot traverse raw block {cid}")
        nxt = None
        if data is not None and data.type == HAMT_SHARD:
            nxt = _hamt_lookup(blocks, node, data, name)
        else:
            for l in node.links:
                if l.name == name:
                    nxt = l.cid
                    break
        if nxt is None:
            raise FileNotFoundError(f"no link named {name!r} under {cid}")
        cid = nxt
    return cid


def export(blocks, cid, dest):
    """Write a UnixFS DAG (file, directory or symlink) to ``dest`` on disk."""
    cid, node, data, raw = load(blocks, cid)
    if node is not None and data is not None and data.type in (DIRECTORY, HAMT_SHARD):
        os.makedirs(dest, exist_ok=True)
        for e in ls(blocks, cid):
            if "/" in e.name or e.name in ("", ".", ".."):
                raise ValueError(f"unsafe entry name {e.name!r}")
            export(blocks, e.cid, os.path.join(dest, e.name))
    elif node is not None and data is not None and data.type == SYMLINK:
        os.symlink(data.data.decode(), dest)
    else:
        with open(dest, "wb") as f:
            for chunk in _cat(blocks, cid, node, data, raw, 0, None):
                f.write(chunk)
    if data is not None and data.mode is not None and data.type != SYMLINK:
        os.chmod(dest, data.mode & 0o7777)


def walk_cids(blocks, cid):
    """Yield every CID in the DAG under ``cid`` (depth first, root first)."""
    stack = [CID.decode(cid)]
    seen = set()
    while stack:
        c = stack.pop()
        if c.multihash in seen:
            continue
        seen.add(c.multihash)
        yield c
        if c.codec == 0x70:
            node = PBNode.decode(blocks.get(c))
            kids = [l.cid for l in node.links]
            if hasattr(blocks, "get_many") and kids:
                blocks.get_many(kids)
            stack.extend(reversed(kids))
        elif c.codec == 0x71:
            from . import dagcbor
            stack.extend(reversed(dagcbor.links(dagcbor.decode(blocks.get(c)))))
