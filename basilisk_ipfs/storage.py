"""Storage limits and automatic garbage collection.

:class:`ManagedBlockstore` wraps a blockstore and keeps it under
``storage_max`` bytes:

* When the store grows past ``high_water`` x ``storage_max`` (default 90%),
  a background collection deletes the least recently used *unpinned* blocks
  until the store is back under ``low_water`` x ``storage_max`` (default 80%).
* Writes made inside a :meth:`session` (imports, ``block_put``, ``pin_add``)
  are held to the hard limit: if a block would not fit even after
  collecting, :class:`StorageFull` is raised and the write is refused.
  Blocks written in a session are protected from collection until the
  session ends, so a half-finished import can't be evicted before it is
  pinned.
* Blocks fetched from the network outside a session are a cache: they
  trigger collection but are never refused.

Blocks used after a collection starts are never evicted by that collection.
"""

import logging
import re
import threading
import time
from contextlib import contextmanager

from .blockstore import Blockstore, StorageFull
from .cid import CID

log = logging.getLogger(__name__)

_UNITS = {"": 1, "b": 1, "kb": 10 ** 3, "mb": 10 ** 6, "gb": 10 ** 9, "tb": 10 ** 12,
          "kib": 2 ** 10, "mib": 2 ** 20, "gib": 2 ** 30, "tib": 2 ** 40}


def parse_size(value) -> int:
    """Accept bytes as an int, or a string like ``"10GB"``, ``"512 MiB"``."""
    if value is None or isinstance(value, int):
        return value
    m = re.fullmatch(r"\s*([\d.]+)\s*([a-zA-Z]*)\s*", str(value))
    if not m or m.group(2).lower() not in _UNITS:
        raise ValueError(f"invalid size {value!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


class ManagedBlockstore(Blockstore):
    def __init__(self, inner: Blockstore, storage_max=None, keep_fn=None,
                 high_water=0.9, low_water=0.8):
        """
        :param inner: the backing blockstore.
        :param storage_max: byte limit (int or string such as ``"10GB"``); None = unlimited.
        :param keep_fn: callable returning the set of multihashes that must
            never be collected (the node passes "everything reachable from a pin").
        """
        if not 0 < low_water <= high_water <= 1:
            raise ValueError("need 0 < low_water <= high_water <= 1")
        self.inner = inner
        self.storage_max = parse_size(storage_max)
        self.keep_fn = keep_fn or (lambda: set())
        self.high_water = high_water
        self.low_water = low_water
        self._gc_lock = threading.Lock()
        self._bg_running = threading.Event()
        self._sessions = []          # list of sets of protected multihashes
        self._sessions_lock = threading.Lock()
        self._local = threading.local()
        self.stats = {"collections": 0, "blocks_evicted": 0, "bytes_evicted": 0}

    # ---- sessions --------------------------------------------------------
    @contextmanager
    def session(self, enforce=True):
        """Protect every block written (or read) by this thread until the
        block exits; if ``enforce``, refuse writes beyond the hard limit."""
        sink = set()
        with self._sessions_lock:
            self._sessions.append(sink)
        prev = getattr(self._local, "stack", None)
        self._local.stack = (prev or []) + [(sink, enforce)]
        try:
            yield sink
        finally:
            self._local.stack = prev
            with self._sessions_lock:
                self._sessions.remove(sink)
            if self.storage_max is not None:
                # blocks this session protected (e.g. a refused or unpinned
                # import) may now be collectable
                self.maybe_collect()

    def protect(self, cid):
        """Protect a block for the duration of the current thread's session."""
        stack = getattr(self._local, "stack", None)
        if stack:
            stack[-1][0].add(CID.decode(cid).multihash)

    def _protected(self):
        with self._sessions_lock:
            out = set()
            for s in self._sessions:
                out |= s
            return out

    def _is_protected(self, mh):
        with self._sessions_lock:
            return any(mh in s for s in self._sessions)

    def _current(self):
        stack = getattr(self._local, "stack", None)
        return stack[-1] if stack else (None, False)

    # ---- Blockstore interface ------------------------------------------------
    def get(self, cid, touch=True):
        data = self.inner.get(cid, touch)
        sink, _ = self._current()
        if sink is not None:
            sink.add(CID.decode(cid).multihash)
        return data

    def put(self, cid, data, verify=True):
        cid = self._check(cid, data, verify)
        sink, enforce = self._current()
        if sink is not None:
            sink.add(cid.multihash)
        if self.storage_max is not None and not self.inner.has(cid):
            if enforce:
                self._make_room(len(data))
            self.inner.put(cid, data, verify=False)
            self.maybe_collect()
        else:
            self.inner.put(cid, data, verify=False)

    def has(self, cid):
        return self.inner.has(cid)

    def delete(self, cid):
        self.inner.delete(cid)

    def keys(self):
        return self.inner.keys()

    def size(self):
        return self.inner.size()

    def lru(self):
        return self.inner.lru()

    # ---- limits ----------------------------------------------------------
    def usage(self) -> dict:
        return {"size": self.size(), "storage_max": self.storage_max,
                "high_water": None if self.storage_max is None else int(self.storage_max * self.high_water),
                "low_water": None if self.storage_max is None else int(self.storage_max * self.low_water)}

    def _make_room(self, incoming: int):
        if self.size() + incoming <= self.storage_max:
            return
        target = min(int(self.storage_max * self.low_water), self.storage_max - incoming)
        self.collect(max(target, 0))
        if self.size() + incoming > self.storage_max:
            what = f"storing {incoming} more bytes would exceed" if incoming else "data exceeds"
            raise StorageFull(
                f"{what} the {self.storage_max}-byte storage limit "
                f"({self.size()} bytes used, all of it pinned or in use)")

    def check_limit(self):
        """Raise StorageFull if the store is over its limit even after collecting."""
        if self.storage_max is not None and self.size() > self.storage_max:
            self._make_room(0)

    def maybe_collect(self):
        """Start a background collection if usage is over the high-water mark."""
        if self.storage_max is None:
            return
        if self.size() <= self.storage_max * self.high_water or self._bg_running.is_set():
            return
        self._bg_running.set()

        def run():
            try:
                self.collect(int(self.storage_max * self.low_water))
            except Exception:
                log.exception("background garbage collection failed")
            finally:
                self._bg_running.clear()

        threading.Thread(target=run, daemon=True, name="auto-gc").start()

    # ---- collection --------------------------------------------------------
    def collect(self, target_size=0):
        """Delete least-recently-used unpinned blocks until the store is at or
        below ``target_size`` bytes (0 = delete every unpinned block).
        Returns ``(blocks_deleted, bytes_freed)``."""
        with self._gc_lock:
            if self.size() <= target_size:
                return 0, 0
            started = time.time()
            keep = self.keep_fn() | self._protected()
            blocks = freed = 0
            for mh, size, last_used in self.inner.lru():
                if self.size() <= target_size:
                    break
                if last_used >= started or mh in keep:
                    continue
                if self._is_protected(mh):  # protected since we started
                    continue
                self.inner.delete(CID(1, "raw", mh))
                blocks += 1
                freed += size
            self.stats["collections"] += 1
            self.stats["blocks_evicted"] += blocks
            self.stats["bytes_evicted"] += freed
            if blocks:
                log.info("gc: evicted %d blocks (%d bytes); %d bytes in use",
                         blocks, freed, self.size())
            return blocks, freed
