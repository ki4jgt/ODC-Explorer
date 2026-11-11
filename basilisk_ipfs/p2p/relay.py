"""Circuit Relay v2.

Spec: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md

* :class:`RelayClient` – what Kubo's ``Swarm.RelayClient`` does:
  - **AutoRelay**: when AutoNAT finds we are not publicly reachable, reserve
    slots on public relays (``RESERVE`` on the hop protocol), announce
    ``<relay addr>/p2p-circuit`` addresses, refresh reservations before they
    expire and keep the relay connections alive;
  - accept connections relayed to us (``CONNECT`` on the stop protocol);
  - dial peers through their ``/p2p-circuit`` addresses (``CONNECT`` on hop).
* :class:`RelayService` – what Kubo's ``Swarm.RelayService`` does: accept
  reservations and relay limited connections between peers.

A relayed stream becomes the raw connection, which is then upgraded with
Noise and Yamux exactly like TCP (the dialing peer is the initiator). Relayed
connections are *limited*; DCUtR (:mod:`.dcutr`) upgrades them to direct.
Messages are varint-length-prefixed protobufs (max 4 KiB).
"""

import logging
import random
import threading
import time

from .. import protobuf as pb
from ..keys import PeerID
from ..multiaddr import Multiaddr
from .addrs import PRIVATE, PUBLIC, is_public
from .host import DialError, read_delimited, write_delimited

log = logging.getLogger(__name__)

HOP = "/libp2p/circuit/relay/0.2.0/hop"
STOP = "/libp2p/circuit/relay/0.2.0/stop"
MAX_MSG = 4096

# HopMessage.Type / StopMessage.Type
RESERVE, CONNECT, HOP_STATUS = 0, 1, 2
STOP_CONNECT, STOP_STATUS = 0, 1
# Status
UNUSED, OK = 0, 100
RESERVATION_REFUSED, RESOURCE_LIMIT_EXCEEDED, PERMISSION_DENIED = 200, 201, 202
CONNECTION_FAILED, NO_RESERVATION = 203, 204
MALFORMED_MESSAGE, UNEXPECTED_MESSAGE = 400, 401
STATUS_NAMES = {0: "UNUSED", 100: "OK", 200: "RESERVATION_REFUSED", 201: "RESOURCE_LIMIT_EXCEEDED",
                202: "PERMISSION_DENIED", 203: "CONNECTION_FAILED", 204: "NO_RESERVATION",
                400: "MALFORMED_MESSAGE", 401: "UNEXPECTED_MESSAGE"}


class RelayError(DialError):
    def __init__(self, status, what=""):
        self.status = status
        super().__init__(f"{what}relay status {STATUS_NAMES.get(status, status)}")


# ---- messages -------------------------------------------------------------
def enc_peer(pid, addrs=()):
    return pb.enc_bytes(1, PeerID.decode(pid).to_bytes()) + b"".join(
        pb.enc_bytes(2, Multiaddr(a).to_bytes()) for a in addrs)


def enc_limit(duration=0, data=0):
    out = b""
    if duration:
        out += pb.enc_varint(1, duration)
    if data:
        out += pb.enc_varint(2, data)
    return out


def hop_message(type, peer=None, reservation=None, limit=None, status=None):
    out = pb.enc_varint(1, type)
    if peer is not None:
        out += pb.enc_bytes(2, peer)
    if reservation is not None:
        out += pb.enc_bytes(3, reservation)
    if limit is not None:
        out += pb.enc_bytes(4, limit)
    if status is not None:
        out += pb.enc_varint(5, status)
    return out


def stop_message(type, peer=None, limit=None, status=None):
    out = pb.enc_varint(1, type)
    if peer is not None:
        out += pb.enc_bytes(2, peer)
    if limit is not None:
        out += pb.enc_bytes(3, limit)
    if status is not None:
        out += pb.enc_varint(4, status)
    return out


def dec_peer(raw):
    m = pb.decode(raw)
    addrs = []
    for a in m.get(2, []):
        try:
            addrs.append(Multiaddr(a))
        except ValueError:
            pass
    return PeerID(pb.first(m, 1)), addrs


def dec_limit(raw):
    if raw is None:
        return None
    m = pb.decode(raw)
    return {"duration": pb.first(m, 1, 0), "data": pb.first(m, 2, 0)}


class StreamConnection:
    """Adapts a relayed stream to the raw-connection interface the
    security handshake expects."""

    def __init__(self, stream, timeout=30.0):
        self.stream = stream
        self.timeout = timeout

    def write(self, data):
        self.stream.write(data, timeout=self.timeout)

    def read_exact(self, n):
        return self.stream.read_exact(n, timeout=self.timeout)

    def close(self):
        self.stream.reset()


class Reservation:
    def __init__(self, relay, expire, addrs, limit, conn):
        self.relay = relay
        self.expire = expire
        self.addrs = addrs
        self.limit = limit
        self.conn = conn

    def circuit_addrs(self):
        out = []
        for a in self.addrs:
            parts = list(Multiaddr(a).parts)
            while parts and parts[-1][0] in ("p2p", "p2p-circuit"):
                parts.pop()  # normalise: some relays repeat their /p2p component
            if not parts:
                continue
            out.append(Multiaddr(parts).encapsulate(f"/p2p/{self.relay}/p2p-circuit"))
        return list(dict.fromkeys(out))

    def __repr__(self):
        return f"<Reservation {self.relay} expires in {int(self.expire - time.time())}s>"


# ---- client ---------------------------------------------------------------
class RelayClient:
    """
    :param auto: reserve relay slots automatically when AutoNAT reports the
        host as not publicly reachable (go-libp2p AutoRelay). ``"always"``
        reserves regardless of reachability.
    :param static_relays: relay multiaddrs to use (``.../p2p/<id>``) instead
        of picking from connected peers.
    :param num_relays: how many reservations to hold.
    """

    def __init__(self, host, auto=True, static_relays=(), num_relays=2,
                 keepalive=30.0, check_interval=30.0):
        self.host = host
        self.auto = auto
        self.static_relays = [Multiaddr(a) for a in static_relays]
        self.num_relays = num_relays
        self.keepalive = keepalive
        self.check_interval = check_interval
        self.reservations = {}  # relay PeerID -> Reservation
        self._failed = {}       # relay PeerID -> time of last refusal
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        host.relay = self
        host.set_stream_handler(STOP, self._handle_stop)
        host.on_disconnect(self._on_disconnect)
        host.addr_manager.on_change(lambda _: self._wake.set())
        if auto:
            threading.Thread(target=self._loop, daemon=True, name="autorelay").start()

    def close(self):
        self._stop.set()
        self._wake.set()

    # ---- reservations ------------------------------------------------------
    def reserve(self, relay) -> Reservation:
        """Make (or refresh) a reservation on ``relay`` (PeerID or multiaddr)."""
        if isinstance(relay, (str, Multiaddr)) and str(relay).startswith("/"):
            conn = self.host.connect(relay)
        else:
            conn = self.host.connect_peer(PeerID.decode(relay))
        if conn.limited:
            raise DialError("cannot reserve over a relayed connection")
        st = conn.new_stream(HOP, timeout=30)
        try:
            write_delimited(st, hop_message(RESERVE))
            m = pb.decode(read_delimited(st, MAX_MSG, timeout=30))
            st.close()
        except Exception:
            st.reset()
            raise
        if pb.first(m, 1) != HOP_STATUS:
            raise RelayError(UNEXPECTED_MESSAGE, "reserve: ")
        status = pb.first(m, 5, UNUSED)
        if status != OK:
            raise RelayError(status, "reserve: ")
        r = pb.decode(pb.first(m, 3, b""))
        addrs = []
        for a in r.get(2, []):
            try:
                addrs.append(Multiaddr(a))
            except ValueError:
                pass
        if not addrs:  # fall back to how we reached the relay
            addrs = [conn.remote_addr.encapsulate(f"/p2p/{conn.remote_peer}")]
        res = Reservation(conn.remote_peer, pb.first(r, 1, int(time.time()) + 3600), addrs,
                          dec_limit(pb.first(m, 4)), conn)
        with self._lock:
            self.reservations[conn.remote_peer] = res
        if self.host.connmgr is not None:  # the reservation dies with the connection
            self.host.connmgr.protect(conn.remote_peer, "relay-reservation")
        self._publish()
        log.info("relay reservation on %s (%d addrs)", conn.remote_peer, len(addrs))
        return res

    def _publish(self):
        with self._lock:
            addrs = [a for r in self.reservations.values() for a in r.circuit_addrs()]
        self.host.addr_manager.set_relay_addrs(addrs)

    def _on_disconnect(self, conn):
        # the reservation is only valid while the relay connection is open
        with self._lock:
            r = self.reservations.get(conn.remote_peer)
            if r is not None and r.conn is conn:
                del self.reservations[conn.remote_peer]
            else:
                return
        if self.host.connmgr is not None:
            self.host.connmgr.unprotect(conn.remote_peer, "relay-reservation")
        log.info("lost relay reservation on %s", conn.remote_peer)
        self._publish()
        self._wake.set()

    def _wanted(self):
        if self.auto == "always" or self.static_relays:
            return True
        return self.host.reachability == PRIVATE

    def _candidates(self):
        if self.static_relays:
            return list(self.static_relays)
        now = time.time()
        out = []
        for p in self.host.peers():
            pi = self.host.peer_info(p)
            if HOP not in pi.protocols or p in self.reservations:
                continue
            if now - self._failed.get(p, 0) < 3600:
                continue
            conns = self.host.connections(p)
            if conns and not conns[0].limited:
                out.append(p)
        random.shuffle(out)
        return out

    def maintain(self):
        """Refresh expiring reservations, drop dead ones, add new ones."""
        now = time.time()
        with self._lock:
            current = list(self.reservations.values())
        for r in current:
            if r.conn.closed or (self.keepalive and not r.conn.session.ping(timeout=10)):
                with self._lock:
                    self.reservations.pop(r.relay, None)
                self._publish()
                continue
            if r.expire - now < 5 * 60:
                try:
                    self.reserve(r.relay)
                except Exception as e:
                    log.info("refreshing reservation on %s failed: %s", r.relay, e)
                    with self._lock:
                        self.reservations.pop(r.relay, None)
                    self._publish()
        if not self._wanted():
            if self.reservations and self.host.reachability == PUBLIC and not self.static_relays:
                with self._lock:
                    self.reservations.clear()  # directly reachable: relays not needed
                self._publish()
            return
        for relay in self._candidates():
            if len(self.reservations) >= self.num_relays:
                break
            try:
                self.reserve(relay)
            except Exception as e:
                log.debug("reservation on %s failed: %s", relay, e)
                pid = relay.peer_id if isinstance(relay, Multiaddr) else relay
                if pid is not None:
                    self._failed[pid] = time.time()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.maintain()
            except Exception:
                log.exception("autorelay failed")
            self._wake.wait(self.check_interval if self._wanted() else 60)
            self._wake.clear()

    # ---- incoming relayed connections (stop) --------------------------------
    def _handle_stop(self, st):
        relay_conn = self.host._conn_for_stream(st)
        m = pb.decode(read_delimited(st, MAX_MSG, timeout=30))
        if pb.first(m, 1) != STOP_CONNECT or 2 not in m or relay_conn is None:
            write_delimited(st, stop_message(STOP_STATUS, status=MALFORMED_MESSAGE))
            st.close()
            return
        src, _ = dec_peer(m[2][0])
        write_delimited(st, stop_message(STOP_STATUS, status=OK))
        remote = Multiaddr(relay_conn.remote_addr).encapsulate(
            f"/p2p/{relay_conn.remote_peer}/p2p-circuit")
        raw = StreamConnection(st)
        try:
            conn = self.host.upgrade(raw, initiator=False, expected=src, remote_addr=remote,
                                     direction="inbound", limited=True)
        except Exception as e:
            log.debug("relayed connection from %s failed: %s", src, e)
            st.reset()
            return
        raw.timeout = None
        log.info("relayed connection from %s via %s", conn.remote_peer, relay_conn.remote_peer)

    # ---- dialing through a relay (hop CONNECT) ----------------------------------
    def dial(self, circuit, peer):
        """Connect to ``peer`` through ``<relay addr>/p2p/<relay>/p2p-circuit``."""
        circuit = Multiaddr(circuit)
        protos = circuit.protocols()
        i = protos.index("p2p-circuit")
        relay_addr = Multiaddr(circuit.parts[:i])
        peer = PeerID.decode(peer)
        relay_conn = self.host.connect(relay_addr)
        st = relay_conn.new_stream(HOP, timeout=30)
        try:
            write_delimited(st, hop_message(CONNECT, peer=enc_peer(peer)))
            m = pb.decode(read_delimited(st, MAX_MSG, timeout=30))
            if pb.first(m, 1) != HOP_STATUS:
                raise RelayError(UNEXPECTED_MESSAGE, "connect: ")
            status = pb.first(m, 5, UNUSED)
            if status != OK:
                raise RelayError(status, "connect: ")
            raw = StreamConnection(st)
            conn = self.host.upgrade(raw, initiator=True, expected=peer,
                                     remote_addr=Multiaddr(circuit.parts[:i + 1]),
                                     direction="outbound", limited=True)
            raw.timeout = None
            return conn
        except Exception:
            st.reset()
            raise


# ---- service --------------------------------------------------------------
class RelayService:
    """Relays limited connections for peers holding a reservation.
    Defaults match go-libp2p: 1 h reservations, 2 min / 128 KiB per circuit."""

    def __init__(self, host, reservation_ttl=3600, limit_duration=120, limit_data=1 << 17,
                 max_reservations=128, max_circuits=16):
        self.host = host
        self.reservation_ttl = reservation_ttl
        self.limit_duration = limit_duration
        self.limit_data = limit_data
        self.max_reservations = max_reservations
        self.max_circuits = max_circuits
        self.reservations = {}  # PeerID -> (expire, conn)
        self._circuits = 0
        self._lock = threading.Lock()
        host.set_stream_handler(HOP, self._handle)

    def _limit(self):
        return enc_limit(self.limit_duration, self.limit_data)

    def _handle(self, st):
        conn = self.host._conn_for_stream(st)
        try:
            m = pb.decode(read_delimited(st, MAX_MSG, timeout=30))
        except ValueError:
            write_delimited(st, hop_message(HOP_STATUS, status=MALFORMED_MESSAGE))
            st.close()
            return
        t = pb.first(m, 1)
        if conn is None or conn.limited:
            write_delimited(st, hop_message(HOP_STATUS, status=PERMISSION_DENIED))
            st.close()
        elif t == RESERVE:
            self._reserve(st, conn)
        elif t == CONNECT and 2 in m:
            self._connect(st, conn, dec_peer(m[2][0])[0])
        else:
            write_delimited(st, hop_message(HOP_STATUS, status=UNEXPECTED_MESSAGE))
            st.close()

    def _reserve(self, st, conn):
        now = time.time()
        with self._lock:
            for p, (exp, c) in list(self.reservations.items()):
                if exp < now or c.closed:
                    del self.reservations[p]
            if conn.remote_peer not in self.reservations and len(self.reservations) >= self.max_reservations:
                write_delimited(st, hop_message(HOP_STATUS, status=RESERVATION_REFUSED))
                st.close()
                return
            expire = int(now) + self.reservation_ttl
            self.reservations[conn.remote_peer] = (expire, conn)
        addrs = [a.encapsulate(f"/p2p/{self.host.peer_id}") for a in self.host.addrs()
                 if "p2p-circuit" not in a.protocols()]
        res = pb.enc_varint(1, expire) + b"".join(pb.enc_bytes(2, a.to_bytes()) for a in addrs)
        write_delimited(st, hop_message(HOP_STATUS, reservation=res, limit=self._limit(), status=OK))
        st.close()

    def _connect(self, src_st, src_conn, target):
        with self._lock:
            entry = self.reservations.get(target)
            if entry is not None and (entry[0] < time.time() or entry[1].closed):
                entry = None
            busy = self._circuits >= self.max_circuits
            if not busy and entry is not None:
                self._circuits += 1
        if entry is None:
            write_delimited(src_st, hop_message(HOP_STATUS, status=NO_RESERVATION))
            src_st.close()
            return
        if busy:
            write_delimited(src_st, hop_message(HOP_STATUS, status=RESOURCE_LIMIT_EXCEEDED))
            src_st.close()
            return
        try:
            dst_st = entry[1].new_stream(STOP, timeout=30)
            write_delimited(dst_st, stop_message(STOP_CONNECT, peer=enc_peer(src_conn.remote_peer),
                                                 limit=self._limit()))
            m = pb.decode(read_delimited(dst_st, MAX_MSG, timeout=30))
            if pb.first(m, 1) != STOP_STATUS or pb.first(m, 4) != OK:
                dst_st.reset()
                raise RelayError(pb.first(m, 4, UNUSED))
        except Exception as e:
            log.debug("relay to %s failed: %s", target, e)
            write_delimited(src_st, hop_message(HOP_STATUS, status=CONNECTION_FAILED))
            src_st.close()
            with self._lock:
                self._circuits -= 1
            return
        write_delimited(src_st, hop_message(HOP_STATUS, limit=self._limit(), status=OK))
        self._bridge(src_st, dst_st)

    def _bridge(self, a, b):
        deadline = time.time() + self.limit_duration if self.limit_duration else None
        done = threading.Event()

        def pump(src, dst):
            sent = 0
            try:
                while not done.is_set():
                    timeout = None if deadline is None else max(0.01, deadline - time.time())
                    data = src.read(65536, timeout=timeout)
                    if not data:
                        dst.close()
                        return
                    sent += len(data)
                    if self.limit_data and sent > self.limit_data:
                        break
                    dst.write(data)
            except Exception:
                pass
            done.set()
            a.reset()
            b.reset()

        t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
        t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        with self._lock:
            self._circuits -= 1
