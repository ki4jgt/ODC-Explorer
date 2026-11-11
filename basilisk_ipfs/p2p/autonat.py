"""AutoNAT v2: per-address reachability checks.

Spec: https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md

Client: asks a server (over ``/libp2p/autonat/2/dial-request``) to dial one of
our addresses. The server proves the dial by sending our random nonce on a
``/libp2p/autonat/2/dial-back`` stream over the new connection; responses
whose nonce we did not receive are discarded. If the server wants to dial an
IP other than the one it observes for us, it first asks for 30-100 kB of
"dial data" (amplification-attack prevention), which we send in chunks of at
most 4096 bytes.

Following the spec's suggestion, an address is considered reachable or
unreachable once ``confidence`` (default 3) servers agree, rechecked
periodically against multiple servers.

Server (optional, :class:`AutoNATService`): dials only the first address it
is willing to dial, never reuses its listen port for dial-backs, demands dial
data when the address IP differs from the observed IP, and rate limits.
"""

import logging
import os
import random
import struct
import threading
import time

from .. import protobuf as pb
from ..multiaddr import Multiaddr
from .addrs import PRIVATE, PUBLIC, UNKNOWN, ip_of
from .host import read_delimited, write_delimited

log = logging.getLogger(__name__)

DIAL_REQUEST = "/libp2p/autonat/2/dial-request"
DIAL_BACK = "/libp2p/autonat/2/dial-back"

# DialStatus
UNUSED, E_DIAL_ERROR, E_DIAL_BACK_ERROR, DIAL_OK = 0, 100, 101, 200
# DialResponse.ResponseStatus
E_INTERNAL_ERROR, E_REQUEST_REJECTED, E_DIAL_REFUSED, RESP_OK = 0, 100, 101, 200
# DialBackResponse.DialBackStatus
DIAL_BACK_OK = 0

MAX_DIAL_DATA = 100_000      # spec suggests servers ask for 30k-100k bytes
DIAL_DATA_CHUNK = 4096       # spec: data field at most 4096 bytes
MAX_MSG = 8192


class AutoNATError(Exception):
    pass


# ---- messages -------------------------------------------------------------
def _fixed64(field, v):
    return pb.enc_fixed64(field, v)


def msg_dial_request(addrs, nonce):
    body = b"".join(pb.enc_bytes(1, Multiaddr(a).to_bytes()) for a in addrs) + _fixed64(2, nonce)
    return pb.enc_bytes(1, body)


def msg_dial_response(status, addr_idx=0, dial_status=UNUSED):
    body = pb.enc_varint(1, status)
    if addr_idx:
        body += pb.enc_varint(2, addr_idx)
    if dial_status:
        body += pb.enc_varint(3, dial_status)
    return pb.enc_bytes(2, body)


def msg_dial_data_request(addr_idx, num_bytes):
    body = (pb.enc_varint(1, addr_idx) if addr_idx else b"") + pb.enc_varint(2, num_bytes)
    return pb.enc_bytes(3, body)


def msg_dial_data_response(data):
    return pb.enc_bytes(4, pb.enc_bytes(1, data))


def decode_message(data):
    """Returns ``(kind, fields)`` where kind is one of 1..4 (the oneof field)."""
    m = pb.decode(data)
    for kind in (1, 2, 3, 4):
        if kind in m:
            return kind, pb.decode(m[kind][0])
    raise AutoNATError("empty AutoNAT message")


# ---- client ---------------------------------------------------------------
class AutoNATClient:
    """Determines which of the host's addresses are publicly reachable and
    reports the result to the host's :class:`AddressManager`."""

    def __init__(self, host, confidence=3, interval=900.0, retry=60.0, timeout=60.0,
                 start=True):
        self.host = host
        self.confidence = confidence
        self.interval = interval
        self.retry = retry
        self.timeout = timeout
        self._pending = {}           # nonce -> threading.Event
        self._results = {}           # Multiaddr -> list of (server, bool), newest last
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        host.set_stream_handler(DIAL_BACK, self._handle_dial_back)
        host.addr_manager.on_change(lambda _: self._wake.set())
        if start:
            threading.Thread(target=self._loop, daemon=True, name="autonat").start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def servers(self):
        return [p for p in self.host.peers() if DIAL_REQUEST in self.host.peer_info(p).protocols]

    # dial-back stream: the server proves it reached us
    def _handle_dial_back(self, st):
        m = pb.decode(read_delimited(st, MAX_MSG, timeout=30))
        nonce = pb.first(m, 1)
        ev = self._pending.get(nonce)
        if ev is not None:
            ev.set()
        write_delimited(st, b"")  # DialBackResponse{status: OK}; OK is the zero value
        st.close()

    def check_address(self, server, addr):
        """Ask ``server`` to dial ``addr``. Returns True (reachable), False
        (unreachable) or None (inconclusive / refused)."""
        addr = Multiaddr(addr)
        nonce = struct.unpack("<Q", os.urandom(8))[0]
        ev = threading.Event()
        self._pending[nonce] = ev
        try:
            st = self.host.new_stream(server, DIAL_REQUEST, timeout=self.timeout)
            try:
                write_delimited(st, msg_dial_request([addr], nonce))
                while True:
                    kind, f = decode_message(read_delimited(st, MAX_MSG, timeout=self.timeout))
                    if kind == 3:  # DialDataRequest: amplification-attack prevention
                        need = pb.first(f, 2, 0)
                        if need > MAX_DIAL_DATA:
                            st.reset()  # spec: reject the cost by resetting
                            return None
                        chunk = msg_dial_data_response(bytes(DIAL_DATA_CHUNK))
                        sent = 0
                        while sent < need:
                            write_delimited(st, chunk)
                            sent += DIAL_DATA_CHUNK
                        continue
                    if kind != 2:
                        raise AutoNATError(f"unexpected AutoNAT message {kind}")
                    break
                st.close()
            except Exception:
                st.reset()
                raise
        finally:
            got_nonce = ev.wait(0.5) or ev.is_set()
            self._pending.pop(nonce, None)
        status = pb.first(f, 1, E_INTERNAL_ERROR)
        dial_status = pb.first(f, 3, UNUSED)
        if status != RESP_OK:
            log.debug("autonat %s: response status %s", server, status)
            return None
        if pb.first(f, 2, 0) != 0:
            return None  # we only sent one address
        if dial_status == DIAL_OK:
            if not got_nonce:
                log.debug("autonat %s claimed OK without a valid dial-back; discarded", server)
                return None
            return True
        if dial_status == E_DIAL_ERROR:
            return False
        return None  # E_DIAL_BACK_ERROR / unknown codes are inconclusive

    def _record(self, addr, server, ok):
        with self._lock:
            hist = [(s, r) for s, r in self._results.get(addr, []) if s != server]
            hist.append((server, ok))
            self._results[addr] = hist[-(2 * self.confidence - 1):]

    def status_of(self, addr):
        with self._lock:
            hist = self._results.get(Multiaddr(addr), [])
        yes = sum(1 for _, r in hist if r)
        no = len(hist) - yes
        if yes >= self.confidence and yes > no:
            return PUBLIC
        if no >= self.confidence and no > yes:
            return PRIVATE
        return UNKNOWN

    def check(self, max_requests=12):
        """Run one round of checks over the candidate addresses."""
        am = self.host.addr_manager
        servers = self.servers()
        random.shuffle(servers)
        requests = 0
        for addr in am.candidates():
            if self.status_of(addr) != UNKNOWN:
                continue
            for server in servers:
                if requests >= max_requests or self.status_of(addr) != UNKNOWN:
                    break
                with self._lock:
                    if any(s == server for s, _ in self._results.get(addr, [])):
                        continue
                requests += 1
                try:
                    res = self.check_address(server, addr)
                except Exception as e:
                    log.debug("autonat request to %s failed: %s", server, e)
                    continue
                if res is not None:
                    self._record(addr, server, res)
        self._publish()

    def _publish(self):
        with self._lock:
            addrs = list(self._results)
        reachable = [a for a in addrs if self.status_of(a) == PUBLIC]
        unreachable = [a for a in addrs if self.status_of(a) == PRIVATE]
        overall = PUBLIC if reachable else PRIVATE if unreachable else UNKNOWN
        self.host.addr_manager.set_reachability(overall, reachable, unreachable)

    def _loop(self):
        while not self._stop.is_set():
            if self.servers() and self.host.addr_manager.candidates():
                try:
                    self.check()
                except Exception:
                    log.exception("autonat check failed")
            undecided = any(self.status_of(a) == UNKNOWN for a in self.host.addr_manager.candidates())
            if not undecided:
                # spec: recheck periodically; forget old verdicts so they are retested
                self._wake.wait(self.interval)
                if not self._wake.is_set():
                    with self._lock:
                        self._results.clear()
            else:
                self._wake.wait(self.retry)
            self._wake.clear()


# ---- server ---------------------------------------------------------------
class AutoNATService:
    """Answers AutoNAT v2 dial requests from other peers."""

    def __init__(self, host, allow_private=False, max_concurrent=2, per_peer_interval=60.0,
                 dial_timeout=15.0, dial_data=(30_000, 100_000)):
        self.host = host
        self.allow_private = allow_private
        self.per_peer_interval = per_peer_interval
        self.dial_timeout = dial_timeout
        self.dial_data = dial_data
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._last = {}
        host.set_stream_handler(DIAL_REQUEST, self._handle)

    def _families(self):
        fams = set()
        for a in self.host.addr_manager.interface_addrs():
            ip = ip_of(a)
            if ip is not None and (ip.is_global or self.allow_private):
                fams.add(ip.version)
        return fams

    def _willing(self, addr):
        ip = ip_of(addr)
        if ip is None or addr.decapsulate_p2p()[0].tcp_target() is None:
            return False
        if not ip.is_global and not self.allow_private:
            return False
        return ip.version in self._families()

    def _handle(self, st):
        conn = self.host._conn_for_stream(st)
        kind, f = decode_message(read_delimited(st, MAX_MSG, timeout=30))
        if kind != 1 or conn is None:
            st.reset()
            return
        now = time.time()
        if now - self._last.get(conn.remote_peer, 0) < self.per_peer_interval or \
                not self._sem.acquire(blocking=False):
            write_delimited(st, msg_dial_response(E_REQUEST_REJECTED))
            st.close()
            return
        self._last[conn.remote_peer] = now
        try:
            addrs = []
            for raw in f.get(1, []):
                try:
                    addrs.append(Multiaddr(raw))
                except ValueError:
                    addrs.append(None)
            nonce = pb.first(f, 2, 0)
            idx = next((i for i, a in enumerate(addrs) if a is not None and self._willing(a)), None)
            if idx is None:
                write_delimited(st, msg_dial_response(E_DIAL_REFUSED))
                st.close()
                return
            addr = addrs[idx]
            if ip_of(addr) != ip_of(conn.remote_addr):
                need = random.randint(*self.dial_data)
                write_delimited(st, msg_dial_data_request(idx, need))
                got = 0
                while got < need:
                    k, df = decode_message(read_delimited(st, MAX_MSG, timeout=30))
                    if k != 4:
                        raise AutoNATError("expected dial data")
                    got += len(pb.first(df, 1, b""))
            write_delimited(st, msg_dial_response(RESP_OK, idx, self._dial_back(addr, conn, nonce)))
            st.close()
        finally:
            self._sem.release()

    def _dial_back(self, addr, conn, nonce):
        try:
            back = self.host._dial_addr(addr.decapsulate_p2p()[0], None,
                                        timeout=self.dial_timeout, reuse_port=False,
                                        quiet=True)
        except Exception as e:
            log.debug("autonat dial-back to %s failed: %s", addr, e)
            return E_DIAL_ERROR
        try:
            st = back.new_stream(DIAL_BACK, timeout=self.dial_timeout)
            write_delimited(st, _fixed64(1, nonce))
            read_delimited(st, MAX_MSG, timeout=self.dial_timeout)  # DialBackResponse
            st.close()
            return DIAL_OK
        except Exception as e:
            log.debug("autonat dial-back stream to %s failed: %s", addr, e)
            return E_DIAL_BACK_ERROR
        finally:
            back.close()
