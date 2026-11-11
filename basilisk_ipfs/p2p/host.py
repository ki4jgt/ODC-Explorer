"""A libp2p host over TCP: Noise security, Yamux multiplexing,
multistream-select protocol negotiation, Identify and Ping."""

import errno
import ipaddress
import logging
import os
import socket
import threading
import time

from .. import protobuf as pb
from .. import varint
from ..keys import Ed25519PrivateKey, PeerID, PublicKey
from ..multiaddr import Multiaddr
from . import multistream, noise, quic, yamux
from .addrs import AddressManager

log = logging.getLogger(__name__)

IDENTIFY = "/ipfs/id/1.0.0"
IDENTIFY_PUSH = "/ipfs/id/push/1.0.0"
PING = "/ipfs/ping/1.0.0"
AGENT_VERSION = "basilisk-ipfs/0.1.0"
PROTOCOL_VERSION = "ipfs/0.1.0"
MAX_MESSAGE = 4 * 1024 * 1024


class DialError(ConnectionError):
    pass


class LimitedConnectionError(DialError):
    """The only connection to the peer is a limited (relayed) one."""


# Protocols allowed on limited relayed connections, as in go-libp2p
# (everything else waits for DCUtR to establish a direct connection).
LIMITED_OK = {"/ipfs/id/1.0.0", "/ipfs/id/push/1.0.0", "/ipfs/ping/1.0.0", "/libp2p/dcutr"}


# ---------------------------------------------------------------------------
# helpers for length-prefixed protobuf messages on streams
# ---------------------------------------------------------------------------
def write_delimited(stream, msg: bytes):
    stream.write(varint.encode(len(msg)) + msg)


def read_delimited(stream, max_size=MAX_MESSAGE, timeout=None) -> bytes:
    n = varint.read(lambda k: stream.read_exact(k, timeout=timeout))
    if n > max_size:
        raise ValueError(f"message of {n} bytes exceeds limit")
    return stream.read_exact(n, timeout=timeout)


class RawConnection:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._closed = False

    def write(self, data):
        self.sock.sendall(data)

    def read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("connection closed")
            buf += chunk
        return bytes(buf)

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()


class _NegotiatingStream:
    """Adapter so multistream can speak over a yamux stream."""

    def __init__(self, st, timeout):
        self.st, self.timeout = st, timeout

    def write(self, data):
        self.st.write(data, timeout=self.timeout)

    def read_exact(self, n):
        return self.st.read_exact(n, timeout=self.timeout)


class Connection:
    def __init__(self, host, secure, session_factory, remote_addr, direction, local_addr=None,
                 limited=False):
        self.host = host
        self.limited = limited  # relayed through a circuit relay (data/duration limits)
        self.local_addr: Multiaddr = local_addr
        self.secure = secure
        self.remote_peer: PeerID = secure.remote_peer
        self.remote_key: PublicKey = secure.remote_key
        self.remote_addr: Multiaddr = remote_addr
        self.direction = direction
        self.opened = time.time()
        self.last_active = self.opened  # updated whenever a stream is opened
        self.session = session_factory(self)

    def new_stream(self, protocols, timeout=30.0):
        self.last_active = time.time()
        st = self.session.open_stream()
        try:
            st.protocol = multistream.select(_NegotiatingStream(st, timeout), protocols)
        except Exception:
            st.reset()
            raise
        return st

    @property
    def closed(self):
        return self.session.closed

    def close(self):
        self.session.close()

    @property
    def relayed(self):
        return self.remote_addr is not None and "p2p-circuit" in self.remote_addr.protocols()

    def __repr__(self):
        kind = " limited" if self.limited else ""
        return f"<Connection {self.direction}{kind} {self.remote_peer} {self.remote_addr}>"


class PeerInfo:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.addrs = set()
        self.protocols = set()
        self.agent_version = None
        self.public_key = None

    def __repr__(self):
        return f"<PeerInfo {self.peer_id} addrs={len(self.addrs)} agent={self.agent_version!r}>"


class Host:
    def __init__(self, identity: Ed25519PrivateKey = None, dial_timeout=10.0, *,
                 announce=None, append_announce=(), no_announce=(), reuse_port=True,
                 observed_threshold=4):
        """
        :param announce: if given, announce exactly these multiaddrs.
        :param append_announce: extra multiaddrs to announce.
        :param no_announce: multiaddrs or CIDRs (``"10.0.0.0/8"``,
            ``"/ip4/10.0.0.0/ipcidr/8"``) never to announce.
        :param reuse_port: dial out from the listen port so peers observe a
            usable public address (Identify observedAddr).
        """
        self.identity = identity or Ed25519PrivateKey()
        self.peer_id = self.identity.peer_id()
        self.dial_timeout = dial_timeout
        self._handlers = {}
        self._conns = {}  # PeerID -> [Connection]
        self._lock = threading.RLock()
        self._dial_locks = {}
        self.peerstore = {}  # PeerID -> PeerInfo
        self._listeners = []
        self.listen_addrs = []
        self._connect_cbs = []
        self._disconnect_cbs = []
        self.closed = False
        self.relay = None  # RelayClient, if enabled: dials /p2p-circuit addresses
        self.connmgr = None  # ConnectionManager, if enabled
        self._expected = {}  # (ip, port) -> (peer, initiator, expiry) during hole punching
        self.reuse_port = reuse_port and hasattr(socket, "SO_REUSEPORT")
        self.addr_manager = AddressManager(self, announce, append_announce, no_announce,
                                           observed_threshold)
        self.addr_manager.on_change(lambda _: self._schedule_push())
        self.set_stream_handler(IDENTIFY, self._handle_identify)
        self.set_stream_handler(IDENTIFY_PUSH, self._handle_identify_push)
        self.set_stream_handler(PING, self._handle_ping)

    # ---- registration ----------------------------------------------------
    def set_stream_handler(self, protocol, handler):
        """``handler(stream)`` runs in its own thread for each inbound stream.
        Connected peers are told about new protocols via identify push."""
        new = protocol not in self._handlers
        self._handlers[protocol] = handler
        if new and getattr(self, "_conns", None):
            self._schedule_push()

    def _schedule_push(self, delay=0.5):
        """Debounced identify push (several changes -> one push)."""
        with self._lock:
            if getattr(self, "_push_timer", None) is not None:
                return
            def fire():
                with self._lock:
                    self._push_timer = None
                self.push_identify()
            self._push_timer = threading.Timer(delay, fire)
            self._push_timer.daemon = True
            self._push_timer.start()

    def remove_stream_handler(self, protocol):
        self._handlers.pop(protocol, None)

    def on_connect(self, cb):
        self._connect_cbs.append(cb)

    def on_disconnect(self, cb):
        self._disconnect_cbs.append(cb)

    def protocols(self):
        return sorted(self._handlers)

    def peer_info(self, peer) -> PeerInfo:
        peer = PeerID.decode(peer)
        with self._lock:
            pi = self.peerstore.get(peer)
            if pi is None:
                pi = self.peerstore[peer] = PeerInfo(peer)
            return pi

    def add_addrs(self, peer, addrs):
        pi = self.peer_info(peer)
        for a in addrs:
            a = Multiaddr(a).decapsulate_p2p()[0]
            pi.addrs.add(a)

    # ---- connections -----------------------------------------------------
    def connections(self, peer=None):
        with self._lock:
            if peer is not None:
                conns = [c for c in self._conns.get(PeerID.decode(peer), []) if not c.closed]
                return sorted(conns, key=lambda c: c.limited)  # direct before relayed
            return [c for cs in self._conns.values() for c in cs if not c.closed]

    def peers(self):
        with self._lock:
            return [p for p, cs in self._conns.items() if any(not c.closed for c in cs)]

    def is_connected(self, peer):
        return bool(self.connections(peer))

    def connect(self, addr, peer_id=None) -> Connection:
        """Dial a multiaddr (ideally ending in /p2p/<id>) or a known peer ID."""
        if isinstance(addr, PeerID) or (isinstance(addr, str) and not addr.startswith("/")):
            return self.connect_peer(PeerID.decode(addr))
        ma = Multiaddr(addr)
        base, pid = ma.decapsulate_p2p()
        pid = pid or (PeerID.decode(peer_id) if peer_id else None)
        if pid is not None:
            existing = self.connections(pid)
            if existing:
                return existing[0]
        return self._dial_addr(base, pid)

    def connect_peer(self, peer: PeerID, addrs=None) -> Connection:
        """Connect to ``peer``: reuse a direct connection, else dial its direct
        addresses, else go through one of its circuit relay addresses."""
        peer = PeerID.decode(peer)
        existing = self.connections(peer)
        if existing and not existing[0].limited:
            return existing[0]
        with self._lock:
            lock = self._dial_locks.setdefault(peer, threading.Lock())
        with lock:
            existing = self.connections(peer)
            if existing and not existing[0].limited:
                return existing[0]
            known = list(addrs or []) + list(self.peer_info(peer).addrs)
            candidates = _order_addrs(known)
            errors = []
            if candidates:
                try:
                    return self._dial_parallel(peer, candidates)
                except DialError as e:
                    errors.append(str(e))
            if existing:
                return existing[0]  # limited relayed connection
            if self.relay is not None:
                for circuit in _circuit_addrs(known):
                    try:
                        return self.relay.dial(circuit, peer)
                    except Exception as e:
                        errors.append(f"{circuit}: {e}")
            raise DialError(f"could not connect to {peer}: " + ("; ".join(errors[:4]) or "no dialable addresses"))

    def _dial_parallel(self, peer, candidates, parallelism=4):
        """Dial several addresses concurrently (staggered); first success wins."""
        result = {}
        errors = []
        done = threading.Event()
        lock = threading.Lock()
        remaining = [len(candidates)]

        def attempt(a):
            try:
                conn = self._dial_addr(Multiaddr(a).decapsulate_p2p()[0], peer)
                with lock:
                    if "conn" in result:
                        conn.close()  # lost the race
                    else:
                        result["conn"] = conn
                        done.set()
            except Exception as e:
                errors.append(f"{a}: {e}")
            finally:
                with lock:
                    remaining[0] -= 1
                    if remaining[0] == 0:
                        done.set()

        sem = threading.Semaphore(parallelism)

        def run(a):
            with sem:
                if not done.is_set():
                    attempt(a)
                else:
                    with lock:
                        remaining[0] -= 1
                        if remaining[0] == 0:
                            done.set()

        for i, a in enumerate(candidates):
            threading.Thread(target=run, args=(a,), daemon=True).start()
            if done.wait(0.25 if i < parallelism else 0):
                break
        done.wait(self.dial_timeout * (1 + len(candidates) // parallelism) + 1)
        if "conn" in result:
            return result["conn"]
        raise DialError(f"could not connect to {peer}: " + ("; ".join(errors[:4]) or "timed out"))

    def _reuse_bind(self, family):
        """The local (host, port) to dial from so the connection leaves from
        a wildcard listen port, or None."""
        if not self.reuse_port:
            return None
        want = "ip6" if family == socket.AF_INET6 else "ip4"
        for a in self.listen_addrs:
            ip, port = a.tcp_target()
            if a.protocols()[0] == want and ip in ("0.0.0.0", "::"):
                return (ip, port)
        return None

    def _connect_socket(self, family, host, port, timeout, reuse_port, fallback=True):
        bind = self._reuse_bind(family) if reuse_port else None
        if bind is not None:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind(bind)
                sock.connect((host, port))
                return sock
            except OSError as e:
                sock.close()
                if not fallback or e.errno not in (errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EINVAL):
                    raise
                # same 4-tuple already in use (e.g. peer dialed us from its
                # listen port): fall back to an ephemeral port
        elif not fallback:
            raise OSError("no listen port to dial from")
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError:
            sock.close()
            raise
        return sock

    def upgrade(self, raw, initiator, expected=None, remote_addr=None, local_addr=None,
                direction="outbound", limited=False, quiet=False) -> Connection:
        """Secure (Noise) and multiplex (Yamux) a raw duplex byte stream, as
        for any transport connection. ``initiator`` runs multistream-select
        and the Noise handshake as the dialer."""
        if initiator:
            multistream.select(raw, noise.PROTOCOL_ID)
            secure = noise.handshake_initiator(raw, self.identity, expected)
            multistream.select(secure, yamux.PROTOCOL_ID)
        else:
            multistream.handle(raw, [noise.PROTOCOL_ID])
            secure = noise.handshake_responder(raw, self.identity)
            if expected is not None and secure.remote_peer != expected:
                raise noise.HandshakeError(f"expected {expected}, got {secure.remote_peer}")
            multistream.handle(secure, [yamux.PROTOCOL_ID])
        return self._add_connection(secure, remote_addr, direction, is_client=initiator,
                                    local_addr=local_addr, quiet=quiet, limited=limited)

    def _dial_addr(self, base: Multiaddr, expected: PeerID = None, timeout=None,
                   reuse_port=True, quiet=False) -> Connection:
        """Dial one address (TCP, or QUIC when available). ``quiet``
        connections (e.g. AutoNAT dial-backs) are not registered, identified
        or announced to callbacks."""
        if self.closed:
            raise DialError("host is closed")
        self._check_fds()
        if quic.quic_target(base) is not None:
            return self._dial_quic(base, expected, timeout, quiet)
        target = _resolve_tcp(base)
        if target is None:
            raise DialError(f"unsupported transport: {base}")
        family, host, port = target
        timeout = timeout or self.dial_timeout
        try:
            sock = self._connect_socket(family, host, port, timeout, reuse_port)
        except OSError as e:
            raise DialError(f"dial {base} failed: {e}") from e
        return self._upgrade_socket(sock, True, expected, base, "outbound", quiet)

    def _check_fds(self):
        """Refuse to dial when nearly every file descriptor is in use, rather
        than failing later with "Too many open files"; ask the connection
        manager to free some."""
        from .connmgr import fd_usage
        usage = fd_usage()
        if usage is not None and usage[0] >= 0.9 * usage[1]:
            if self.connmgr is not None:
                self.connmgr._wake.set()
            raise DialError(f"open-file limit nearly reached ({usage[0]}/{usage[1]} in use)")

    def _dial_quic(self, base, expected=None, timeout=None, quiet=False) -> Connection:
        if not quic.AVAILABLE:
            raise DialError(f"QUIC unavailable: {quic.ERROR}")
        try:
            sess = quic.dial(self.identity, base, expected, timeout or self.dial_timeout)
        except Exception as e:
            raise DialError(f"dial {base} failed: {e}") from e

        def factory(conn):
            sess.start(on_stream=lambda st: self._handle_inbound(conn, st),
                       on_close=lambda s: None if quiet else self._on_conn_closed(conn))
            return sess

        return self._add_connection(sess, base, "outbound", is_client=True,
                                    local_addr=sess.local_addr, quiet=quiet,
                                    session_factory=factory)

    def dial_simultaneous(self, addr, peer, initiator, timeout=None) -> Connection:
        """TCP simultaneous open for hole punching (DCUtR): dial ``addr``
        from our listen port. ``initiator`` decides the security role, since
        both sides are dialing."""
        base = Multiaddr(addr).decapsulate_p2p()[0]
        target = _resolve_tcp(base)
        if target is None:
            raise DialError(f"unsupported transport: {base}")
        family, host, port = target
        try:
            sock = self._connect_socket(family, host, port, timeout or self.dial_timeout,
                                        True, fallback=False)
        except OSError as e:
            raise DialError(f"hole punch to {base} failed: {e}") from e
        return self._upgrade_socket(sock, initiator, PeerID.decode(peer), base, "outbound", False)

    def _upgrade_socket(self, sock, initiator, expected, remote, direction, quiet):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(self.dial_timeout)
            local = _sockaddr_to_ma(sock.getsockname())
            raw = RawConnection(sock)
            # register only after the handshake succeeds
            conn = self.upgrade(raw, initiator, expected, remote, local, direction, quiet=quiet)
            sock.settimeout(None)
            return conn
        except Exception as e:
            sock.close()
            raise DialError(f"connection to {remote} failed: {e}") from e

    def _add_connection(self, secure, addr, direction, is_client, local_addr=None,
                        quiet=False, limited=False, session_factory=None) -> Connection:
        """Register a secured connection. ``secure`` provides remote_peer /
        remote_key; the muxer is Yamux unless ``session_factory`` supplies
        one (QUIC brings its own streams)."""
        def factory(conn):
            return yamux.YamuxSession(secure, is_client,
                                      on_stream=lambda st: self._handle_inbound(conn, st),
                                      on_close=lambda s: None if quiet else self._on_conn_closed(conn))

        conn = Connection(self, secure, session_factory or factory, addr, direction, local_addr,
                          limited)
        if quiet:
            return conn
        with self._lock:
            closing = self.closed
            if not closing:
                self._conns.setdefault(conn.remote_peer, []).append(conn)
        if closing:  # a dial that finished after close(): don't leak it
            conn.close()
            raise DialError("host is closed")
        pi = self.peer_info(conn.remote_peer)
        pi.public_key = conn.remote_key
        if direction == "outbound" and addr is not None and not limited:
            pi.addrs.add(addr)
        log.info("connected %s %s", direction, conn.remote_peer)
        threading.Thread(target=self._identify_peer, args=(conn,), daemon=True).start()
        for cb in list(self._connect_cbs):
            try:
                cb(conn)
            except Exception:
                log.exception("connect callback failed")
        return conn

    def _on_conn_closed(self, conn):
        with self._lock:
            lst = self._conns.get(conn.remote_peer, [])
            if conn in lst:
                lst.remove(conn)
            if not lst:
                self._conns.pop(conn.remote_peer, None)
        log.info("disconnected %s", conn.remote_peer)
        for cb in list(self._disconnect_cbs):
            try:
                cb(conn)
            except Exception:
                log.exception("disconnect callback failed")

    def disconnect(self, peer):
        for c in self.connections(peer):
            c.close()

    def new_stream(self, peer, protocols, timeout=30.0, allow_limited=False):
        """Open a stream to ``peer`` (PeerID, Connection, or multiaddr) speaking
        one of ``protocols``. Connects if necessary. Like go-libp2p, streams
        are only opened on a limited (relayed) connection for protocols that
        are meant to run there, or when ``allow_limited`` is set."""
        if isinstance(peer, Connection):
            conn = peer
        elif isinstance(peer, (Multiaddr,)) or (isinstance(peer, str) and peer.startswith("/")):
            conn = self.connect(peer)
        else:
            conn = self.connect_peer(PeerID.decode(peer))
        protos = [protocols] if isinstance(protocols, str) else list(protocols)
        if conn.limited and not allow_limited and not set(protos) & LIMITED_OK:
            raise LimitedConnectionError(
                f"only a limited relayed connection to {conn.remote_peer} (awaiting hole punch)")
        return conn.new_stream(protocols, timeout)

    def _handle_inbound(self, conn, st):
        conn.last_active = time.time()
        try:
            proto = multistream.handle(_NegotiatingStream(st, 30.0), self._handlers)
        except Exception as e:
            log.debug("inbound negotiation failed: %s", e)
            st.reset()
            return
        st.protocol = proto
        try:
            self._handlers[proto](st)
        except (EOFError, OSError) as e:  # peer went away / connection closed
            log.debug("handler %s ended: %s", proto, e)
            st.reset()
        except Exception:
            log.exception("handler for %s failed", proto)
            st.reset()

    # ---- listening -------------------------------------------------------
    def listen(self, addr="/ip4/0.0.0.0/tcp/0") -> Multiaddr:
        ma = Multiaddr(addr)
        target = ma.tcp_target()
        if target is None:
            raise ValueError(f"can only listen on TCP: {ma}")
        host, port = target
        family = socket.AF_INET6 if ma.protocols()[0] == "ip6" else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.reuse_port:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((host, port))
        sock.listen(128)
        bound = Multiaddr(f"/{ma.protocols()[0]}/{host}/tcp/{sock.getsockname()[1]}")
        self._listeners.append(sock)
        self.listen_addrs.append(bound)
        threading.Thread(target=self._accept_loop, args=(sock,), daemon=True, name="accept").start()
        log.info("listening on %s/p2p/%s", bound, self.peer_id)
        return bound

    def _accept_loop(self, sock):
        while not self.closed:
            try:
                client, addr = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._accept_one, args=(client, addr), daemon=True).start()

    def expect_simultaneous(self, addr, peer, initiator, ttl=15.0):
        """During a hole punch, a connection from ``addr`` may land on our
        listener instead of completing a simultaneous open. Upgrade it with
        the role DCUtR assigned rather than as a plain inbound connection."""
        ip, port = Multiaddr(addr).decapsulate_p2p()[0].tcp_target()
        with self._lock:
            self._expected[(str(ipaddress.ip_address(ip)), port)] = (
                PeerID.decode(peer), initiator, time.time() + ttl)

    def _accept_one(self, client, addr):
        remote = _sockaddr_to_ma(addr)
        initiator, expected = False, None
        with self._lock:
            key = (remote.parts[0][1], int(remote.parts[1][1]))
            entry = self._expected.get(key)
            if entry is not None and entry[2] > time.time():
                expected, initiator = entry[0], entry[1]
            for k, v in list(self._expected.items()):
                if v[2] <= time.time():
                    del self._expected[k]
        try:
            self._upgrade_socket(client, initiator, expected, remote, "inbound", False)
        except DialError as e:
            log.debug("inbound handshake from %s failed: %s", addr, e)

    def addrs(self):
        """The addresses we announce (see :class:`AddressManager`)."""
        return self.addr_manager.addrs()

    def public_addrs(self):
        return self.addr_manager.public_addrs()

    @property
    def reachability(self):
        """'public', 'private' or 'unknown' (determined by AutoNAT)."""
        return self.addr_manager.reachability

    def close(self):
        self.closed = True
        for s in self._listeners:
            try:
                s.close()
            except OSError:
                pass
        for c in self.connections():
            c.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- identify ----------------------------------------------------------
    def _identify_msg(self, conn) -> bytes:
        msg = pb.enc_bytes(5, PROTOCOL_VERSION) + pb.enc_bytes(6, AGENT_VERSION)
        msg += pb.enc_bytes(1, self.identity.public_key.to_protobuf())
        for a in self.addrs():
            msg += pb.enc_bytes(2, a.to_bytes())
        try:
            msg += pb.enc_bytes(4, conn.remote_addr.to_bytes())
        except Exception:
            pass
        for p in self.protocols():
            msg += pb.enc_bytes(3, p)
        return msg

    def _handle_identify(self, st):
        write_delimited(st, self._identify_msg(self._conn_for_stream(st)))
        st.close()

    def _conn_for_stream(self, st):
        for c in self.connections():
            if c.session is st.session:
                return c
        return None

    def _handle_identify_push(self, st):
        data = read_delimited(st, timeout=30)
        conn = self._conn_for_stream(st)
        if conn:
            self._apply_identify(conn, data)
        st.close()

    def _apply_identify(self, conn, data):
        m = pb.decode(data)
        pi = self.peer_info(conn.remote_peer)
        if 4 in m:
            try:
                self.addr_manager.record_observation(conn, Multiaddr(m[4][0]))
            except (ValueError, IndexError):
                pass
        if 6 in m:
            pi.agent_version = m[6][0].decode(errors="replace")
        if 3 in m:
            pi.protocols = {p.decode(errors="replace") for p in m[3]}
        for a in m.get(2, []):
            try:
                pi.addrs.add(Multiaddr(a))
            except ValueError:
                pass
        return pi

    def _identify_peer(self, conn):
        try:
            st = conn.new_stream(IDENTIFY, timeout=30)
            data = read_delimited(st, timeout=30)
            st.close()
            self._apply_identify(conn, data)
        except Exception as e:
            log.debug("identify %s failed: %s", conn.remote_peer, e)

    def push_identify(self):
        """Send our current Identify info to every connected peer
        (``/ipfs/id/push/1.0.0``), e.g. after our addresses changed."""
        def push(conn):
            try:
                st = conn.new_stream(IDENTIFY_PUSH, timeout=15)
                write_delimited(st, self._identify_msg(conn))
                st.close()
            except Exception as e:
                log.debug("identify push to %s failed: %s", conn.remote_peer, e)

        for conn in self.connections():
            if IDENTIFY_PUSH in self.peer_info(conn.remote_peer).protocols:
                threading.Thread(target=push, args=(conn,), daemon=True).start()

    def identify(self, peer) -> PeerInfo:
        """Run identify against a connected peer and return what it reports."""
        conn = self.connect_peer(PeerID.decode(peer)) if not isinstance(peer, Connection) else peer
        st = conn.new_stream(IDENTIFY)
        data = read_delimited(st, timeout=30)
        st.close()
        return self._apply_identify(conn, data)

    # ---- ping ------------------------------------------------------------
    def _handle_ping(self, st):
        while True:
            try:
                data = st.read_exact(32, timeout=60)
            except (EOFError, TimeoutError):
                st.close()
                return
            st.write(data)

    def ping(self, peer, count=1):
        """Returns a list of round-trip times in seconds."""
        st = self.new_stream(peer, PING)
        rtts = []
        try:
            for _ in range(count):
                payload = os.urandom(32)
                t = time.perf_counter()
                st.write(payload)
                if st.read_exact(32, timeout=30) != payload:
                    raise ConnectionError("ping payload mismatch")
                rtts.append(time.perf_counter() - t)
        finally:
            st.close()
        return rtts


def _circuit_addrs(addrs):
    """Relay addresses (``.../p2p/<relay>/p2p-circuit``) whose relay we can dial."""
    out = []
    for a in addrs:
        a = Multiaddr(a)
        protos = a.protocols()
        if "p2p-circuit" not in protos:
            continue
        i = protos.index("p2p-circuit")
        relay = Multiaddr(a.parts[:i])
        if relay.peer_id is not None and dialable(relay):
            out.append(Multiaddr(a.parts[:i + 1]))
    return list(dict.fromkeys(out))


def dialable(ma) -> bool:
    """Can this host dial ``ma`` directly (TCP, or QUIC when OpenSSL has it)?"""
    base = Multiaddr(ma).decapsulate_p2p()[0]
    return base.tcp_target() is not None or quic.dialable(base)


def _order_addrs(addrs):
    """Directly dialable addresses: public first, then private, then
    loopback; within each, QUIC before TCP (as Kubo prefers)."""
    out = {}
    for a in addrs:
        a = Multiaddr(a)
        base = a.decapsulate_p2p()[0]
        if not dialable(base):
            continue
        v = base.parts[0][1]
        try:
            ip = ipaddress.ip_address(v)
            rank = 2 if ip.is_loopback else 1 if ip.is_private or ip.is_link_local else 0
        except ValueError:
            rank = 0
        out[str(base)] = (rank, 0 if quic.quic_target(base) else 1, base)
    return [b for _, _, b in sorted(out.values(), key=lambda t: t[:2])]


def _sockaddr_to_ma(sa):
    ip = ipaddress.ip_address(sa[0].split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return Multiaddr(f"/ip{ip.version}/{ip}/tcp/{sa[1]}")


def _resolve_tcp(ma: Multiaddr):
    t = ma.tcp_target()
    if t is None:
        return None
    host, port = t
    proto = ma.protocols()[0]
    if proto == "ip4":
        return socket.AF_INET, host, port
    if proto == "ip6":
        return socket.AF_INET6, host, port
    fam = {"dns4": socket.AF_INET, "dns6": socket.AF_INET6}.get(proto, 0)
    infos = socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM)
    if not infos:
        raise DialError(f"cannot resolve {host}")
    f, _, _, _, sa = infos[0]
    return f, sa[0], port


def _local_ips(version=4):
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    for target in (("8.8.8.8", 80), ("2001:4860:4860::8888", 80)):
        try:
            fam = socket.AF_INET6 if ":" in target[0] else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect(target)
                ips.add(s.getsockname()[0])
        except OSError:
            pass
    ips.add("127.0.0.1" if version == 4 else "::1")
    want = [ip for ip in ips if (":" in ip) == (version == 6) and "%" not in ip]
    return sorted(want)
