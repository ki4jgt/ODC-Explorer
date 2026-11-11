"""Keeping content findable: DHT (re)providing and IPNS republishing, as
Kubo does.

Provider records expire on DHT servers after 48 h, so every announced key is
re-announced every ``interval`` (Kubo's ``Provide.DHT.Interval``, 22 h).
Which keys are announced follows ``strategy`` (Kubo's ``Provide.Strategy``):

* ``"all"``    - every block in the blockstore (Kubo's default)
* ``"pinned"`` - every block of every pinned DAG
* ``"roots"``  - only the root CIDs of pins

When each key was last announced is persisted (SQLite in the repo), so a
restart only announces what is actually due. Keys are processed in DHT
keyspace order by a pool of workers; failures are retried with backoff.

IPNS records are republished every 4 h (Kubo's ``Ipns.RepublishPeriod``)
with a fresh 48 h validity and an incremented sequence number.
"""

import hashlib
import logging
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .cid import CID

log = logging.getLogger(__name__)

STRATEGIES = ("all", "pinned", "roots")
DEFAULT_INTERVAL = 22 * 3600
RETRY_BACKOFF = (60, 300, 1800, 3600)
IPNS_REPUBLISH_PERIOD = 4 * 3600


class ProviderState:
    """Last-announced timestamps per multihash; SQLite-backed when ``path`` is given."""

    def __init__(self, path=None):
        self._lock = threading.Lock()
        self._mem = {}
        self._db = None
        if path:
            self._db = sqlite3.connect(path, check_same_thread=False)
            self._db.execute("CREATE TABLE IF NOT EXISTS provided (mh BLOB PRIMARY KEY, ts REAL NOT NULL)")
            self._db.commit()
            self._mem = dict(self._db.execute("SELECT mh, ts FROM provided"))

    def get(self, mh):
        return self._mem.get(mh)

    def set_many(self, items):
        with self._lock:
            for mh, ts in items:
                self._mem[mh] = ts
            if self._db is not None:
                self._db.executemany("INSERT OR REPLACE INTO provided (mh, ts) VALUES (?, ?)", items)
                self._db.commit()

    def delete_many(self, mhs):
        with self._lock:
            for mh in mhs:
                self._mem.pop(mh, None)
            if self._db is not None:
                self._db.executemany("DELETE FROM provided WHERE mh = ?", [(m,) for m in mhs])
                self._db.commit()

    def keys(self):
        return list(self._mem)

    def __len__(self):
        return len(self._mem)

    def close(self):
        if self._db is not None:
            with self._lock:
                self._db.close()
                self._db = None


class Provider:
    """Announces (and re-announces) content to the DHT for an IPFSNode.

    :param strategy: ``"all"``, ``"pinned"`` or ``"roots"``.
    :param interval: seconds between re-announcements of a key.
    :param workers: concurrent DHT announcements.
    :param state_path: SQLite file for last-announced times (None = memory).
    :param scan_every: how often to look for keys that have become due.
    :param addr_wait: seconds to wait, after starting, for a public or relay
        address before announcing anyway (records carry our addresses).
    """

    def __init__(self, node, strategy="all", interval=DEFAULT_INTERVAL, workers=8,
                 state_path=None, scan_every=600.0, addr_wait=180.0, clock=time.time,
                 provide_fn=None, start=True):
        if strategy not in STRATEGIES:
            raise ValueError(f"provide strategy must be one of {STRATEGIES}")
        self.node = node
        self.strategy = strategy
        self.interval = interval
        self.workers = workers
        self.scan_every = scan_every
        self.addr_wait = addr_wait
        self.clock = clock
        self.provide_fn = provide_fn or (lambda cid: node.dht.provide(cid, timeout=60))
        self.state = ProviderState(state_path)
        self._failures = {}   # mh -> (count, retry_at)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._started_at = clock()
        self.stats = {"passes": 0, "provided": 0, "failed": 0, "last_pass": None,
                      "last_pass_duration": None}
        if start:
            threading.Thread(target=self._loop, daemon=True, name="reprovider").start()

    # ---- which keys --------------------------------------------------------
    def keys(self):
        """Multihashes that should be announced under the current strategy."""
        if self.strategy == "all":
            return set(self.node.blockstore.keys())
        if self.strategy == "pinned":
            return self.node._pinned_multihashes() & set(self.node.blockstore.keys())
        return {c.multihash for c in self.node.pin_ls()}

    def due(self, keys=None, now=None):
        """Keys never announced, or last announced more than ``interval`` ago."""
        now = self.clock() if now is None else now
        out = []
        for mh in (self.keys() if keys is None else keys):
            last = self.state.get(mh)
            if last is not None and now - last < self.interval:
                continue
            fail = self._failures.get(mh)
            if fail is not None and fail[1] > now:
                continue
            out.append(mh)
        # DHT keyspace order: consecutive lookups share most of their path
        out.sort(key=lambda mh: hashlib.sha256(mh).digest())
        return out

    # ---- announcing --------------------------------------------------------
    def _announce(self, mh):
        try:
            sent = self.provide_fn(CID(1, "raw", mh))
        except Exception as e:
            log.debug("provide %s failed: %s", mh.hex(), e)
            sent = 0
        return mh, sent

    def _record(self, results):
        now = self.clock()
        ok = [(mh, now) for mh, sent in results if sent]
        if ok:
            self.state.set_many(ok)
        for mh, _ in ok:
            self._failures.pop(mh, None)
        for mh, sent in results:
            if not sent:
                count = self._failures.get(mh, (0, 0))[0]
                delay = RETRY_BACKOFF[min(count, len(RETRY_BACKOFF) - 1)]
                self._failures[mh] = (count + 1, now + delay)
        self.stats["provided"] += len(ok)
        self.stats["failed"] += len(results) - len(ok)

    def provide_now(self, cids):
        """Announce ``cids`` immediately (blocking). Returns how many succeeded."""
        mhs = [CID.decode(c).multihash for c in cids]
        with ThreadPoolExecutor(self.workers) as ex:
            results = list(ex.map(self._announce, mhs))
        self._record(results)
        return sum(1 for _, sent in results if sent)

    def run_once(self):
        """One pass: announce everything that is due. Returns counts."""
        start = self.clock()
        keys = self.keys()
        todo = self.due(keys)
        # forget keys that are gone (deleted by GC, unpinned)
        stale = [mh for mh in self.state.keys() if mh not in keys]
        if stale:
            self.state.delete_many(stale)
        for mh in list(self._failures):
            if mh not in keys:
                del self._failures[mh]
        results = []
        if todo:
            log.info("providing %d of %d keys (strategy %s)", len(todo), len(keys), self.strategy)
            with ThreadPoolExecutor(self.workers) as ex:
                for i in range(0, len(todo), 256):  # persist progress in batches
                    if self._stop.is_set():
                        break
                    batch = list(ex.map(self._announce, todo[i:i + 256]))
                    self._record(batch)
                    results += batch
        self.stats["passes"] += 1
        self.stats["last_pass"] = start
        self.stats["last_pass_duration"] = self.clock() - start
        ok = sum(1 for _, s in results if s)
        return {"due": len(todo), "provided": ok, "failed": len(results) - ok, "keys": len(keys)}

    def notify(self):
        """New blocks or pins: announce what is due soon (debounced)."""
        self._wake.set()

    def _addresses_ready(self):
        """Provider records carry our addresses, so wait until they are ones
        others can use: AutoNAT confirmed a public address, or (when we are
        behind a NAT) relay addresses exist. Give up waiting after
        ``addr_wait`` seconds."""
        from .p2p.addrs import PUBLIC
        host = self.node.host
        if host.reachability == PUBLIC or host.addr_manager.relay_addrs():
            return True
        if host.addr_manager.announce is not None or host.addr_manager.append_announce:
            return True  # addresses configured by hand
        return self.clock() - self._started_at >= self.addr_wait

    def _loop(self):
        while not self._stop.is_set():
            self._wake.wait(self.scan_every)
            if self._stop.is_set():
                break
            self._wake.clear()
            time.sleep(2)  # debounce bursts of new blocks
            if not self._addresses_ready():
                self._wake.set()
                time.sleep(5)
                continue
            try:
                self.run_once()
            except Exception:
                log.exception("reprovide pass failed")

    def status(self):
        keys = self.keys()
        return {"strategy": self.strategy, "interval": self.interval, "keys": len(keys),
                "due": len(self.due(keys)), "tracked": len(self.state),
                "retrying": len(self._failures), **self.stats}

    def close(self):
        self._stop.set()
        self._wake.set()
        self.state.close()


class IPNSRepublisher:
    """Republishes the node's IPNS records before they expire."""

    def __init__(self, node, period=IPNS_REPUBLISH_PERIOD, check_every=600.0, start=True):
        self.node = node
        self.period = period
        self.check_every = check_every
        self._stop = threading.Event()
        if start:
            threading.Thread(target=self._loop, daemon=True, name="ipns-republisher").start()

    def run_once(self):
        """Republish every record whose last publication is older than ``period``.
        Returns the names republished."""
        done = []
        now = time.time()
        for name, info in list(self.node._ipns_published.items()):
            key = self.node._ipns_keys.get(name)
            if key is None or now - info["published"] < self.period:
                continue
            rec = self.node._local_records.get(name)
            if rec is None:
                continue
            try:
                self.node.name_publish(rec.path, key=key, lifetime=info["lifetime"])
                done.append(name)
                log.info("republished IPNS %s -> %s", name, rec.path)
            except Exception as e:
                log.warning("republishing IPNS %s failed: %s", name, e)
        return done

    def _loop(self):
        delay = 30.0  # first check soon after start (records may be overdue)
        while not self._stop.wait(delay):
            delay = self.check_every
            try:
                self.run_once()
            except Exception:
                log.exception("IPNS republish failed")

    def close(self):
        self._stop.set()
