"""Connection manager and file-descriptor limits, modelled on Kubo.

Kubo's basic connection manager (``Swarm.ConnMgr``) lets connections grow to
``HighWater`` (96), then closes the least valuable ones until ``LowWater``
(32) remain. Connections younger than ``GracePeriod`` (20 s) and protected
peers are never closed. Subsystems express how valuable a peer is with tags:
here Bitswap tags peers that recently delivered blocks, the DHT tags routing
table peers, and relay reservations and configured peers are protected.

Kubo also raises the process's soft file-descriptor limit (``IPFS_FD_MAX``,
8192 by default); :func:`raise_fd_limit` does the same, and the host refuses
new dials when nearly all descriptors are in use instead of failing with
"Too many open files".
"""

import logging
import os
import threading
import time

log = logging.getLogger(__name__)

DEFAULT_FD_LIMIT = 8192


def raise_fd_limit(target=DEFAULT_FD_LIMIT):
    """Raise the soft RLIMIT_NOFILE towards ``target`` (never above the hard
    limit, never lowering it). Returns the resulting soft limit or None."""
    try:
        import resource
    except ImportError:  # Windows: no per-process fd rlimit to raise
        return None
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = target if hard == resource.RLIM_INFINITY else min(target, hard)
    if soft != resource.RLIM_INFINITY and soft < want:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            log.info("raised open-file limit from %d to %d", soft, want)
            return want
        except (ValueError, OSError) as e:
            log.warning("could not raise open-file limit from %d: %s", soft, e)
    return soft


def fd_usage():
    """(open descriptors, soft limit), or None where it can't be measured."""
    try:
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft == resource.RLIM_INFINITY:
            return None
        return len(os.listdir("/proc/self/fd")), soft
    except (ImportError, OSError):
        return None


class ConnectionManager:
    def __init__(self, host, low_water=32, high_water=96, grace_period=20.0,
                 check_interval=10.0, start=True):
        if not 0 <= low_water <= high_water:
            raise ValueError("need 0 <= low_water <= high_water")
        self.host = host
        self.low_water = low_water
        self.high_water = high_water
        self.grace_period = grace_period
        self.check_interval = check_interval
        self._tags = {}        # PeerID -> {tag: value}
        self._protected = {}   # PeerID -> {tags}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self.stats = {"trims": 0, "closed": 0}
        host.connmgr = self
        host.on_connect(self._on_connect)
        if start:
            threading.Thread(target=self._loop, daemon=True, name="connmgr").start()

    # ---- tags and protection (as in go-libp2p's ConnManager) -------------------
    def tag_peer(self, peer, tag, value):
        with self._lock:
            self._tags.setdefault(peer, {})[tag] = value

    def untag_peer(self, peer, tag):
        with self._lock:
            t = self._tags.get(peer)
            if t:
                t.pop(tag, None)
                if not t:
                    del self._tags[peer]

    def protect(self, peer, tag):
        with self._lock:
            self._protected.setdefault(peer, set()).add(tag)

    def unprotect(self, peer, tag):
        """Returns True if the peer is still protected under another tag."""
        with self._lock:
            tags = self._protected.get(peer)
            if not tags:
                return False
            tags.discard(tag)
            if not tags:
                del self._protected[peer]
                return False
            return True

    def is_protected(self, peer):
        return bool(self._protected.get(peer))

    def value(self, peer):
        return sum(self._tags.get(peer, {}).values())

    # ---- trimming --------------------------------------------------------------
    def trim(self, target=None):
        """Close the least valuable connections until at most ``target``
        (default ``low_water``) remain. Returns how many were closed."""
        target = self.low_water if target is None else target
        conns = self.host.connections()
        if len(conns) <= target:
            return 0
        now = time.time()
        by_peer = {}
        for c in conns:
            by_peer.setdefault(c.remote_peer, []).append(c)
        candidates = []
        for peer, cs in by_peer.items():
            if self.is_protected(peer):
                continue
            if any(now - c.opened < self.grace_period for c in cs):
                continue
            last = max(getattr(c, "last_active", c.opened) for c in cs)
            candidates.append((self.value(peer), last, peer, cs))
        candidates.sort(key=lambda t: (t[0], t[1]))  # least valuable, then least recently used
        excess = len(conns) - target
        closed = 0
        for _, _, peer, cs in candidates:
            if closed >= excess:
                break
            for c in cs:
                c.close()
                closed += 1
        if closed:
            self.stats["trims"] += 1
            self.stats["closed"] += closed
            log.info("connection manager closed %d connections (%d -> %d)",
                     closed, len(conns), len(conns) - closed)
        return closed

    def _over_limit(self):
        if len(self.host.connections()) > self.high_water:
            return True
        usage = fd_usage()
        return usage is not None and usage[0] > 0.8 * usage[1]

    def _on_connect(self, conn):
        if self._over_limit():
            self._wake.set()

    def _loop(self):
        while not self._stop.is_set():
            self._wake.wait(self.check_interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                if self._over_limit():
                    self.trim()
            except Exception:
                log.exception("connection trimming failed")
            time.sleep(1.0)  # don't trim more than once a second

    def close(self):
        self._stop.set()
        self._wake.set()
