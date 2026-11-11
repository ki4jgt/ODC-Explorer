"""Block storage backends. Blocks are keyed by multihash, so CIDv0/v1 and
codec variants of the same content share storage.

Every backend tracks its total size and when each block was last used
(stored or read), which the garbage collector uses to evict the oldest
blocks first.
"""

import os
import tempfile
import threading
import time
from collections import OrderedDict

from . import multibase
from .cid import CID


class BlockNotFound(KeyError):
    pass


class StorageFull(OSError):
    """Raised when a write would exceed the storage limit and garbage
    collection cannot free enough unpinned space."""


class Blockstore:
    def get(self, cid, touch: bool = True) -> bytes: raise NotImplementedError
    def put(self, cid, data: bytes, verify: bool = True): raise NotImplementedError
    def has(self, cid) -> bool: raise NotImplementedError
    def delete(self, cid): raise NotImplementedError
    def keys(self): raise NotImplementedError  # yields multihash bytes

    def size(self) -> int:
        """Total bytes of block data stored."""
        raise NotImplementedError

    def lru(self):
        """Return ``[(multihash, size, last_used)]``, least recently used first."""
        raise NotImplementedError

    def put_block(self, data: bytes, codec="raw", version=1, hash_fn="sha2-256") -> CID:
        cid = CID.from_data(data, codec, version, hash_fn)
        self.put(cid, data, verify=False)
        return cid

    def __contains__(self, cid):
        return self.has(cid)

    @staticmethod
    def _check(cid, data, verify):
        cid = CID.decode(cid)
        if verify and not cid.verify(data):
            raise ValueError(f"block data does not match {cid}")
        return cid


class MemoryBlockstore(Blockstore):
    def __init__(self):
        self._blocks = OrderedDict()  # multihash -> data, least recently used first
        self._used = {}               # multihash -> last-used timestamp
        self._size = 0
        self._lock = threading.Lock()

    def get(self, cid, touch=True):
        mh = CID.decode(cid).multihash
        with self._lock:
            try:
                data = self._blocks[mh]
            except KeyError:
                raise BlockNotFound(str(cid)) from None
            if touch:
                self._blocks.move_to_end(mh)
                self._used[mh] = time.time()
            return data

    def put(self, cid, data, verify=True):
        cid = self._check(cid, data, verify)
        mh = cid.multihash
        with self._lock:
            if mh in self._blocks:
                self._blocks.move_to_end(mh)
            else:
                self._blocks[mh] = bytes(data)
                self._size += len(data)
            self._used[mh] = time.time()

    def has(self, cid):
        return CID.decode(cid).multihash in self._blocks

    def delete(self, cid):
        mh = CID.decode(cid).multihash
        with self._lock:
            data = self._blocks.pop(mh, None)
            self._used.pop(mh, None)
            if data is not None:
                self._size -= len(data)

    def keys(self):
        return list(self._blocks)

    def size(self):
        return self._size

    def lru(self):
        with self._lock:
            return [(mh, len(d), self._used.get(mh, 0.0)) for mh, d in self._blocks.items()]

    def __len__(self):
        return len(self._blocks)


class FilesystemBlockstore(Blockstore):
    """Stores each block as a file named by its base32 multihash, sharded by
    the next-to-last two characters (the flatfs ``next-to-last/2`` scheme).

    A block's last-used time is its file's mtime, so the eviction order
    survives restarts. Reads refresh it at most once a minute per block.
    """

    TOUCH_INTERVAL = 60.0

    def __init__(self, path):
        self.path = os.path.abspath(path)
        os.makedirs(self.path, exist_ok=True)
        self._lock = threading.Lock()
        self._index = {}  # multihash -> [size, last_used]
        self._size = 0
        for root, _, files in os.walk(self.path):
            for fn in files:
                if not fn.endswith(".data"):
                    continue
                try:
                    st = os.stat(os.path.join(root, fn))
                    mh = multibase.decode("B" + fn[:-5])
                except (OSError, ValueError):
                    continue
                self._index[mh] = [st.st_size, st.st_mtime]
                self._size += st.st_size

    def _file(self, mh: bytes):
        name = multibase.encode(mh, "base32upper")[1:]
        return os.path.join(self.path, name[-3:-1], name + ".data")

    def get(self, cid, touch=True):
        mh = CID.decode(cid).multihash
        fn = self._file(mh)
        try:
            with open(fn, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise BlockNotFound(str(cid)) from None
        if touch:
            now = time.time()
            with self._lock:
                entry = self._index.get(mh)
                stale = entry is not None and now - entry[1] > self.TOUCH_INTERVAL
                if entry is not None:
                    entry[1] = now
            if stale:
                try:
                    os.utime(fn, (now, now))
                except OSError:
                    pass
        return data

    def put(self, cid, data, verify=True):
        cid = self._check(cid, data, verify)
        mh = cid.multihash
        fn = self._file(mh)
        now = time.time()
        if os.path.exists(fn):
            with self._lock:
                entry = self._index.setdefault(mh, [len(data), now])
                entry[1] = now
            try:
                os.utime(fn, (now, now))
            except OSError:
                pass
            return
        os.makedirs(os.path.dirname(fn), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(fn))
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, fn)
        with self._lock:
            if mh not in self._index:
                self._size += len(data)
            self._index[mh] = [len(data), now]

    def has(self, cid):
        return os.path.exists(self._file(CID.decode(cid).multihash))

    def delete(self, cid):
        mh = CID.decode(cid).multihash
        try:
            os.remove(self._file(mh))
        except FileNotFoundError:
            pass
        with self._lock:
            entry = self._index.pop(mh, None)
            if entry is not None:
                self._size -= entry[0]

    def keys(self):
        with self._lock:
            return list(self._index)

    def size(self):
        return self._size

    def lru(self):
        with self._lock:
            items = [(mh, e[0], e[1]) for mh, e in self._index.items()]
        items.sort(key=lambda t: t[2])
        return items
