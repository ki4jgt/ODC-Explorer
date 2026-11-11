"""DCUtR: Direct Connection Upgrade through Relay (TCP hole punching).

Spec: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md

When a peer A reaches us (B) through a relay, B - the inbound side - first
tries to dial A directly. If that fails, B opens ``/libp2p/dcutr`` on the
relayed connection, sends ``CONNECT`` with its observed addresses and starts a
timer; A answers ``CONNECT`` with its own; B measures the RTT, sends ``SYNC``
and waits RTT/2 before dialing, while A dials as soon as ``SYNC`` arrives, so
both TCP SYNs cross (simultaneous open). A acts as the client (security
initiator), B as the server. B makes up to three attempts.

Both sides dial from their listen port, so the NAT reuses the mapping peers
have already observed.
"""

import logging
import threading
import time

from .. import protobuf as pb
from ..multiaddr import Multiaddr
from .addrs import is_public
from .host import read_delimited, write_delimited

log = logging.getLogger(__name__)

PROTOCOL = "/libp2p/dcutr"
CONNECT, SYNC = 100, 300
MAX_MSG = 4096
GRACE = 60.0  # keep the relayed connection this long after a direct one exists


def _is_loopback(ma):
    v = ma.parts[0][1] if ma.parts else ""
    return v.startswith("127.") or v == "::1"


def encode(type, addrs=()):
    return pb.enc_varint(1, type) + b"".join(pb.enc_bytes(2, Multiaddr(a).to_bytes()) for a in addrs)


def decode(data):
    m = pb.decode(data)
    addrs = []
    for raw in m.get(2, []):
        try:
            addrs.append(Multiaddr(raw))
        except ValueError:
            pass
    return pb.first(m, 1), addrs


class HolePunchService:
    def __init__(self, host, attempts=3, addr_fn=None, dial_timeout=8.0):
        self.host = host
        self.attempts = attempts
        self.addr_fn = addr_fn or self.default_addrs
        self.dial_timeout = dial_timeout
        self.stats = {"attempts": 0, "successes": 0}
        host.set_stream_handler(PROTOCOL, self._handle)
        host.on_connect(self._on_connect)

    # addresses we offer: observed public TCP addresses (incl. ones AutoNAT
    # found unreachable - those are exactly the ones hole punching opens),
    # router mappings, then any other direct TCP address we have
    def default_addrs(self):
        am = self.host.addr_manager
        out = list(am.observed_addrs(include_unconfirmed=True))
        with am._lock:
            out += list(am._nat)
        out += [a for a in am.interface_addrs()]  # same-LAN peers
        return [a for a in dict.fromkeys(out)
                if a.tcp_target() is not None and not _is_loopback(a)]

    @staticmethod
    def _dialable(addrs):
        return [a.decapsulate_p2p()[0] for a in addrs
                if "p2p-circuit" not in a.protocols() and a.decapsulate_p2p()[0].tcp_target()]

    def _expect(self, peer, addrs, initiator):
        for a in self._dialable(addrs):
            self.host.expect_simultaneous(a, peer, initiator, ttl=self.dial_timeout + 35)

    def _has_direct(self, peer):
        return any(not c.limited for c in self.host.connections(peer))

    def _race(self, peer, addrs, initiator):
        """Dial all addresses in parallel; True once a direct connection exists
        (ours, or one the peer's simultaneous dial made via our listener).
        Per the spec, attempts that complete after the first one are dropped."""
        done = threading.Event()
        lock = threading.Lock()
        winner = []

        def one(a):
            try:
                conn = self.host.dial_simultaneous(a, peer, initiator, timeout=self.dial_timeout)
            except Exception as e:
                log.debug("hole punch dial %s failed: %s", a, e)
                return
            with lock:
                if winner:
                    conn.close()
                    return
                winner.append(conn)
            done.set()

        for a in addrs:
            self.host.expect_simultaneous(a, peer, initiator, ttl=self.dial_timeout + 5)
        threads = [threading.Thread(target=one, args=(a,), daemon=True) for a in addrs]
        for t in threads:
            t.start()
        end = time.monotonic() + self.dial_timeout + 2
        while time.monotonic() < end and not self._has_direct(peer):
            if done.wait(0.05) or not any(t.is_alive() for t in threads):
                break
        return self._has_direct(peer)

    def _retire_relayed(self, peer):
        def close_later():
            time.sleep(GRACE)
            for c in self.host.connections(peer):
                if c.limited and self._has_direct(peer):
                    c.close()
        threading.Thread(target=close_later, daemon=True).start()

    # ---- B: the side that received the relayed connection -------------------
    def _on_connect(self, conn):
        if conn.limited and conn.direction == "inbound":
            threading.Thread(target=self._punch, args=(conn,), daemon=True, name="dcutr").start()

    def _punch(self, conn):
        peer = conn.remote_peer
        pi = self.host.peer_info(peer)
        end = time.monotonic() + 10  # let identify finish
        while PROTOCOL not in pi.protocols and time.monotonic() < end and not conn.closed:
            time.sleep(0.1)
        # 1. unilateral direct dial if the peer has public addresses
        public = [a for a in self._dialable(list(pi.addrs)) if is_public(a)]
        for a in public[:4]:
            try:
                self.host._dial_addr(a, peer, timeout=5)
                log.info("direct connection to %s without hole punching", peer)
                self._retire_relayed(peer)
                return
            except Exception:
                pass
        if PROTOCOL not in pi.protocols:
            return
        # 2. coordinated simultaneous open
        for attempt in range(1, self.attempts + 1):
            if conn.closed or self._has_direct(peer):
                break
            self.stats["attempts"] += 1
            try:
                st = conn.new_stream(PROTOCOL, timeout=30)
                ours = self.addr_fn()
                t0 = time.monotonic()
                write_delimited(st, encode(CONNECT, ours))
                kind, theirs = decode(read_delimited(st, MAX_MSG, timeout=30))
                rtt = time.monotonic() - t0
                if kind != CONNECT:
                    st.reset()
                    raise ValueError("expected CONNECT")
                self._expect(peer, theirs, initiator=False)
                write_delimited(st, encode(SYNC))
                st.close()
                targets = self._dialable(theirs)
                if not targets:
                    log.info("hole punch with %s: peer sent no TCP addresses", peer)
                    return
                time.sleep(rtt / 2)
                if self._race(peer, targets, initiator=False):
                    self.stats["successes"] += 1
                    log.info("hole punch with %s succeeded (attempt %d, rtt %.0f ms)",
                             peer, attempt, rtt * 1000)
                    self._retire_relayed(peer)
                    return
            except Exception as e:
                log.debug("hole punch attempt %d with %s failed: %s", attempt, peer, e)
        log.info("hole punch with %s failed", peer)

    # ---- A: the side that dialed through the relay --------------------------
    def _handle(self, st):
        conn = self.host._conn_for_stream(st)
        kind, theirs = decode(read_delimited(st, MAX_MSG, timeout=30))
        if kind != CONNECT or conn is None:
            st.reset()
            return
        # register our role before replying: B may dial as soon as it gets
        # our CONNECT, and its SYN can reach our listener before SYNC arrives
        self._expect(conn.remote_peer, theirs, initiator=True)
        write_delimited(st, encode(CONNECT, self.addr_fn()))
        kind, _ = decode(read_delimited(st, MAX_MSG, timeout=30))
        st.close()
        if kind != SYNC:
            return
        targets = self._dialable(theirs)
        self.stats["attempts"] += 1
        if targets and self._race(conn.remote_peer, targets, initiator=True):
            self.stats["successes"] += 1
            log.info("hole punch with %s succeeded", conn.remote_peer)
            self._retire_relayed(conn.remote_peer)
