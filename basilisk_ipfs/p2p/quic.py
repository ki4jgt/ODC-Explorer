"""libp2p over QUIC (RFC 9000, ``/quic-v1``) using OpenSSL's QUIC stack via ctypes.

Specs: https://github.com/libp2p/specs/blob/master/quic/README.md
       https://github.com/libp2p/specs/blob/master/tls/tls.md

OpenSSL >= 3.2 provides a QUIC client (TLS 1.3 handshake, packet protection,
loss recovery, congestion and flow control, streams); this module adds what
libp2p needs on top:

* a self-signed X.509 certificate with a fresh P-256 key, carrying the libp2p
  public-key extension (OID 1.3.6.1.4.1.53594.1.1): our identity key and its
  signature over ``"libp2p-tls-handshake:" || certificate SubjectPublicKeyInfo``;
* ALPN ``libp2p``; both sides present certificates (mutual authentication);
* verification of the peer's certificate exactly as the spec requires (one
  certificate, valid self-signature, current validity period, no unknown
  critical extensions, valid extension signature, expected peer ID);
* QUIC streams adapted to the same interface as Yamux streams, so every
  protocol (multistream-select per stream, identify, bitswap, DHT ...) runs
  unchanged.

OpenSSL 3.2-3.4 can only *dial* QUIC. If libssl lacks QUIC (older OpenSSL,
no OpenSSL), ``AVAILABLE`` is False and ``/quic-v1`` addresses are simply not
dialable; TCP (Noise + Yamux) keeps working.
"""

import ctypes
import datetime
import ipaddress
import selectors
import logging
import os
import socket
import sys
import threading
import time

from .. import protobuf as pb  # noqa: F401  (kept for symmetry with other transports)
from ..keys import PeerID, PublicKey
from ..multiaddr import Multiaddr
from .yamux import StreamClosed, StreamReset

log = logging.getLogger(__name__)

AVAILABLE = False
ERROR = None
ALPN = b"libp2p"
EXTENSION_OID = "1.3.6.1.4.1.53594.1.1"
SIG_PREFIX = b"libp2p-tls-handshake:"
CERT_LIFETIME = datetime.timedelta(days=365)

# OpenSSL constants
_SSL_ERROR_WANT_READ, _SSL_ERROR_WANT_WRITE, _SSL_ERROR_ZERO_RETURN = 2, 3, 6
_STREAM_STATE_RESET_REMOTE, _STREAM_STATE_CONN_CLOSED = 5, 6
_DEFAULT_STREAM_MODE_NONE = 0
_INCOMING_STREAM_POLICY_ACCEPT = 1
_SHUTDOWN_FLAG_RAPID = 1
_SHUTDOWN_FLAG_NO_BLOCK = 4
_STREAM_FLAG_NO_BLOCK = 2
_ACCEPT_STREAM_NO_BLOCK = 1
_SSL_VERIFY_NONE = 0

_P = ctypes.c_void_p
_I = ctypes.c_int
_U64 = ctypes.c_uint64
_SZ = ctypes.c_size_t


# ---------------------------------------------------------------------------
# loading libssl
# ---------------------------------------------------------------------------
def _ssl_candidates():
    try:
        import _ssl  # noqa: F401
        with open("/proc/self/maps") as f:
            for line in f:
                path = line.rsplit(None, 1)[-1]
                if "/libssl" in path and ".so" in path:
                    yield path
    except (ImportError, OSError):
        pass
    if sys.platform == "darwin":
        for prefix in ("/opt/homebrew/opt/openssl@3", "/usr/local/opt/openssl@3"):
            yield os.path.join(prefix, "lib", "libssl.3.dylib")
        return
    if sys.platform == "win32":
        yield from ("libssl-3-x64", "libssl-3")
    yield "libssl.so.3"


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Lib:
    def __init__(self, ssl, crypto):
        def fn(lib, name, restype, *argtypes):
            f = getattr(lib, name)
            f.restype = restype
            f.argtypes = list(argtypes)
            setattr(self, name, f)

        s, c = ssl, crypto
        fn(s, "OSSL_QUIC_client_method", _P)
        fn(s, "SSL_get_event_timeout", _I, _P, ctypes.POINTER(_Timeval), ctypes.POINTER(_I))
        fn(s, "SSL_get_conn_close_info", _I, _P, _P, _SZ)
        fn(s, "SSL_CTX_new", _P, _P)
        fn(s, "SSL_CTX_free", None, _P)
        fn(s, "SSL_CTX_set_alpn_protos", _I, _P, ctypes.c_char_p, ctypes.c_uint)
        fn(s, "SSL_CTX_use_certificate", _I, _P, _P)
        fn(s, "SSL_CTX_use_PrivateKey", _I, _P, _P)
        fn(s, "SSL_CTX_check_private_key", _I, _P)
        fn(s, "SSL_CTX_set_verify", None, _P, _I, _P)
        fn(s, "SSL_new", _P, _P)
        fn(s, "SSL_free", None, _P)
        fn(s, "SSL_set_bio", None, _P, _P, _P)
        fn(s, "SSL_set1_initial_peer_addr", _I, _P, _P)
        fn(s, "SSL_set_default_stream_mode", _I, _P, ctypes.c_uint32)
        fn(s, "SSL_set_incoming_stream_policy", _I, _P, _I, _U64)
        fn(s, "SSL_set_blocking_mode", _I, _P, _I)
        fn(s, "SSL_connect", _I, _P)
        fn(s, "SSL_get_error", _I, _P, _I)
        fn(s, "SSL_handle_events", _I, _P)
        fn(s, "SSL_new_stream", _P, _P, _U64)
        fn(s, "SSL_accept_stream", _P, _P, _U64)
        fn(s, "SSL_get_stream_id", _U64, _P)
        fn(s, "SSL_read_ex", _I, _P, _P, _SZ, ctypes.POINTER(_SZ))
        fn(s, "SSL_write_ex", _I, _P, ctypes.c_char_p, _SZ, ctypes.POINTER(_SZ))
        fn(s, "SSL_stream_conclude", _I, _P, _U64)
        fn(s, "SSL_stream_reset", _I, _P, _P, _SZ)
        fn(s, "SSL_get_stream_read_state", _I, _P)
        fn(s, "SSL_shutdown_ex", _I, _P, _U64, _P, _SZ)
        fn(s, "SSL_get1_peer_certificate", _P, _P)
        fn(s, "SSL_get_peer_cert_chain", _P, _P)
        fn(s, "SSL_get0_alpn_selected", None, _P, ctypes.POINTER(_P), ctypes.POINTER(ctypes.c_uint))
        fn(c, "BIO_new_dgram", _P, _I, _I)
        fn(c, "BIO_ADDR_new", _P)
        fn(c, "BIO_ADDR_free", None, _P)
        fn(c, "BIO_ADDR_rawmake", _I, _P, _I, ctypes.c_char_p, _SZ, ctypes.c_ushort)
        fn(c, "d2i_X509", _P, _P, ctypes.POINTER(_P), ctypes.c_long)
        fn(c, "i2d_X509", _I, _P, ctypes.POINTER(_P))
        fn(c, "X509_free", None, _P)
        fn(c, "X509_verify", _I, _P, _P)
        fn(c, "X509_get0_pubkey", _P, _P)
        fn(c, "i2d_PUBKEY", _I, _P, ctypes.POINTER(_P))
        fn(c, "EVP_PKEY_CTX_new_from_name", _P, _P, ctypes.c_char_p, ctypes.c_char_p)
        fn(c, "EVP_PKEY_keygen_init", _I, _P)
        fn(c, "EVP_PKEY_CTX_set_group_name", _I, _P, ctypes.c_char_p)
        fn(c, "EVP_PKEY_generate", _I, _P, ctypes.POINTER(_P))
        fn(c, "EVP_PKEY_CTX_free", None, _P)
        fn(c, "EVP_PKEY_free", None, _P)
        fn(c, "EVP_MD_CTX_new", _P)
        fn(c, "EVP_MD_CTX_free", None, _P)
        fn(c, "EVP_sha256", _P)
        fn(c, "EVP_DigestSignInit", _I, _P, _P, _P, _P, _P)
        fn(c, "EVP_DigestSign", _I, _P, _P, ctypes.POINTER(_SZ), ctypes.c_char_p, _SZ)
        fn(c, "OPENSSL_sk_num", _I, _P)
        fn(c, "ERR_get_error", ctypes.c_ulong)
        fn(c, "ERR_error_string_n", None, ctypes.c_ulong, ctypes.c_char_p, _SZ)
        fn(c, "ERR_clear_error", None)

    def error(self):
        msgs = []
        while True:
            code = self.ERR_get_error()
            if not code:
                break
            buf = ctypes.create_string_buffer(256)
            self.ERR_error_string_n(code, buf, 256)
            msgs.append(buf.value.decode(errors="replace"))
        return "; ".join(msgs) or "unknown OpenSSL error"


_lib = None


def _load():
    global _lib, AVAILABLE, ERROR
    if os.environ.get("BASILISK_IPFS_PURE_PYTHON") or os.environ.get("BASILISK_IPFS_NO_QUIC"):
        ERROR = "disabled by environment"
        return
    from ..crypto import _openssl
    if not _openssl.AVAILABLE:
        ERROR = f"libcrypto unavailable: {_openssl.ERROR}"
        return
    errors = []
    for cand in dict.fromkeys(_ssl_candidates()):
        try:
            ssl = ctypes.CDLL(cand)
            _lib = _Lib(ssl, _openssl.LIB)
            AVAILABLE = True
            return
        except (OSError, AttributeError) as e:  # missing QUIC symbols: OpenSSL < 3.2
            errors.append(f"{cand}: {e}")
    ERROR = "; ".join(errors) or "libssl not found"


# ---------------------------------------------------------------------------
# DER helpers for the libp2p certificate
# ---------------------------------------------------------------------------
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(enc))
    return _tlv(0x06, out)


def _int(n):
    b = n.to_bytes((n.bit_length() + 8) // 8 or 1, "big")
    return _tlv(0x02, b)


def _time(dt):
    dt = dt.astimezone(datetime.timezone.utc)
    if dt.year < 2050:
        return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())
    return _tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode())


def _items(buf):
    """Iterate DER TLVs in ``buf``: (tag, content, raw)."""
    off = 0
    while off < len(buf):
        start = off
        tag = buf[off]
        ln = buf[off + 1]
        off += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[off:off + n], "big")
            off += n
        content = buf[off:off + ln]
        off += ln
        if off > len(buf):
            raise ValueError("truncated DER")
        yield tag, content, buf[start:off]


def _parse_time(tag, content):
    s = content.decode()
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)


_ECDSA_SHA256 = _seq(_oid("1.2.840.10045.4.3.2"))
_KNOWN_EXTENSIONS = {_oid(EXTENSION_OID), _oid("2.5.29.19"), _oid("2.5.29.15"),
                     _oid("2.5.29.37"), _oid("2.5.29.14"), _oid("2.5.29.35")}


def build_certificate(identity, spki_der, sign_fn, now=None):
    """DER certificate per the libp2p TLS spec; ``sign_fn(tbs)`` signs with the
    certificate key (ECDSA P-256 / SHA-256)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    signed_key = _seq(_tlv(0x04, identity.public_key.to_protobuf()),
                      _tlv(0x04, identity.sign(SIG_PREFIX + spki_der)))
    extension = _seq(_oid(EXTENSION_OID), _tlv(0x04, signed_key))
    name = _seq(_tlv(0x31, _seq(_oid("2.5.4.5"), _tlv(0x13, b"1"))))  # serialNumber=1
    tbs = _seq(
        _tlv(0xA0, _int(2)),                                   # v3
        _int(int.from_bytes(os.urandom(8), "big") >> 1 or 1),  # serial
        _ECDSA_SHA256, name,
        _seq(_time(now - datetime.timedelta(hours=1)), _time(now + CERT_LIFETIME)),
        name, spki_der,
        _tlv(0xA3, _seq(extension)))
    return _seq(tbs, _ECDSA_SHA256, _tlv(0x03, b"\x00" + sign_fn(tbs)))


def verify_certificate(der, now=None):
    """Check a peer certificate's libp2p properties (the self-signature is
    checked separately by OpenSSL). Returns the peer's identity PublicKey."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    (_, cert, _), = list(_items(der))
    tbs = list(_items(next(_items(cert))[1]))
    i = 1 if tbs[0][0] == 0xA0 else 0
    validity = list(_items(tbs[i + 3][1]))
    not_before = _parse_time(validity[0][0], validity[0][1])
    not_after = _parse_time(validity[1][0], validity[1][1])
    if not not_before <= now <= not_after:
        raise ValueError("certificate not within its validity period")
    spki_raw = tbs[i + 5][2]
    signed_key = None
    for tag, content, _ in tbs[i + 6:]:
        if tag != 0xA3:
            continue
        for _, ext, _ in _items(next(_items(content))[1]):
            fields = list(_items(ext))
            oid_raw = fields[0][2]
            critical = len(fields) == 3 and fields[1][0] == 0x01 and fields[1][1] != b"\x00"
            if oid_raw == _oid(EXTENSION_OID):
                signed_key = fields[-1][1]
            elif critical and oid_raw not in _KNOWN_EXTENSIONS:
                raise ValueError("unknown critical certificate extension")
    if signed_key is None:
        raise ValueError("certificate lacks the libp2p public key extension")
    (_, sk, _), = list(_items(signed_key))
    (_, key_pb, _), (_, sig, _) = list(_items(sk))
    key = PublicKey.from_protobuf(key_pb)
    if not key.verify(SIG_PREFIX + spki_raw, sig):
        raise ValueError("invalid libp2p extension signature")
    return key


# ---------------------------------------------------------------------------
# TLS context with our certificate
# ---------------------------------------------------------------------------
class _Context:
    def __init__(self, identity):
        L = _lib
        self.created = time.time()
        pkey = _P()
        kctx = L.EVP_PKEY_CTX_new_from_name(None, b"EC", None)
        try:
            if (not kctx or L.EVP_PKEY_keygen_init(kctx) != 1
                    or L.EVP_PKEY_CTX_set_group_name(kctx, b"P-256") != 1
                    or L.EVP_PKEY_generate(kctx, ctypes.byref(pkey)) != 1):
                raise OSError(f"certificate key generation failed: {L.error()}")
        finally:
            if kctx:
                L.EVP_PKEY_CTX_free(kctx)
        self.pkey = pkey.value
        spki = _i2d(L.i2d_PUBKEY, self.pkey)

        def sign(tbs):
            md = L.EVP_MD_CTX_new()
            try:
                if L.EVP_DigestSignInit(md, None, L.EVP_sha256(), None, self.pkey) != 1:
                    raise OSError(L.error())
                n = _SZ(0)
                L.EVP_DigestSign(md, None, ctypes.byref(n), tbs, len(tbs))
                sig = ctypes.create_string_buffer(n.value)
                if L.EVP_DigestSign(md, sig, ctypes.byref(n), tbs, len(tbs)) != 1:
                    raise OSError(L.error())
                return sig.raw[:n.value]
            finally:
                L.EVP_MD_CTX_free(md)

        der = build_certificate(identity, spki, sign)
        buf = ctypes.create_string_buffer(der, len(der))
        ptr = _P(ctypes.addressof(buf))
        self.x509 = L.d2i_X509(None, ctypes.byref(ptr), len(der))
        if not self.x509:
            raise OSError(f"could not load generated certificate: {L.error()}")
        self.ctx = L.SSL_CTX_new(L.OSSL_QUIC_client_method())
        if not self.ctx:
            raise OSError(f"SSL_CTX_new failed: {L.error()}")
        alpn = bytes([len(ALPN)]) + ALPN
        if (L.SSL_CTX_set_alpn_protos(self.ctx, alpn, len(alpn)) != 0
                or L.SSL_CTX_use_certificate(self.ctx, self.x509) != 1
                or L.SSL_CTX_use_PrivateKey(self.ctx, self.pkey) != 1
                or L.SSL_CTX_check_private_key(self.ctx) != 1):
            raise OSError(f"TLS context setup failed: {L.error()}")
        # the peer's self-signed certificate is verified by us after the handshake
        L.SSL_CTX_set_verify(self.ctx, _SSL_VERIFY_NONE, None)


def _i2d(func, obj):
    n = func(obj, None)
    if n <= 0:
        raise OSError(_lib.error())
    buf = ctypes.create_string_buffer(n)
    ptr = _P(ctypes.addressof(buf))
    func(obj, ctypes.byref(ptr))
    return buf.raw[:n]


_contexts = {}
_ctx_lock = threading.Lock()


def _context(identity):
    pid = identity.peer_id()
    with _ctx_lock:
        c = _contexts.get(pid)
        # certificates are reused, but renewed well before they expire
        if c is None or time.time() - c.created > CERT_LIFETIME.total_seconds() / 2:
            c = _contexts[pid] = _Context(identity)
        return c


# ---------------------------------------------------------------------------
# streams and connections
# ---------------------------------------------------------------------------
class QuicStream:
    """A bidirectional QUIC stream with the same interface as YamuxStream.

    Incoming data is delivered by the connection's event loop; writes are
    non-blocking OpenSSL calls made by the caller (waiting on the loop when
    flow control is exhausted). Only the event loop frees the OpenSSL object,
    and only under ``_io``, which every other OpenSSL call on it also holds.
    """

    def __init__(self, session, ssl_stream):
        self.session = session
        self._s = ssl_stream
        self.id = _lib.SSL_get_stream_id(ssl_stream)
        self.protocol = None
        self._cond = threading.Condition()
        self._buf = bytearray()
        self._remote_closed = False   # FIN received
        self._reset = False
        self._local_closed = False    # FIN sent (or reset)
        self._read_done = False       # nothing more will arrive
        self._freed = False
        self._io = threading.RLock()

    # ---- called by the event loop -------------------------------------------
    def _pump(self, buf, n):
        """Read whatever is available. Returns True if data arrived."""
        got = False
        with self._io:
            if self._freed or self._read_done:
                return False
            while True:
                if _lib.SSL_read_ex(self._s, buf, len(buf), ctypes.byref(n)) == 1:
                    with self._cond:
                        self._buf += buf.raw[:n.value]
                        self._cond.notify_all()
                    got = True
                    continue
                err = _lib.SSL_get_error(self._s, 0)
                _lib.ERR_clear_error()
                if err == _SSL_ERROR_WANT_READ:
                    return got
                with self._cond:
                    if err == _SSL_ERROR_ZERO_RETURN:
                        self._remote_closed = True
                    else:
                        self._reset = True
                    self._read_done = True
                    self._cond.notify_all()
                return True

    def _freeable(self):
        return not self._freed and self._read_done and (self._local_closed or self._reset)

    def _free(self):
        with self._io:
            if self._freed:
                return
            self._freed = True
            _lib.SSL_free(self._s)
        with self._cond:
            self._reset = self._reset or not self._remote_closed
            self._read_done = True
            self._cond.notify_all()

    # ---- reading (same semantics as YamuxStream) -----------------------------
    def _take(self, n):
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read(self, n=-1, timeout=None):
        with self._cond:
            while not self._buf:
                if self._reset:
                    raise StreamReset(f"QUIC stream {self.id} reset")
                if self._remote_closed:
                    return b""
                if not self._cond.wait(timeout):
                    raise TimeoutError("QUIC read timed out")
            return self._take(len(self._buf) if n < 0 else n)

    def read_exact(self, n, timeout=None):
        with self._cond:
            while len(self._buf) < n:
                if self._reset:
                    raise StreamReset(f"QUIC stream {self.id} reset")
                if self._remote_closed:
                    raise StreamClosed("stream closed by peer")
                if not self._cond.wait(timeout):
                    raise TimeoutError("QUIC read timed out")
            return self._take(n)

    def read_all(self, timeout=None):
        out = bytearray()
        while True:
            chunk = self.read(timeout=timeout)
            if not chunk:
                return bytes(out)
            out += chunk

    # ---- writing ---------------------------------------------------------------
    def write(self, data, timeout=None):
        mv = memoryview(bytes(data))
        n = _SZ()
        deadline = None if timeout is None else time.monotonic() + timeout
        while mv:
            with self._io:
                if self._reset or self._freed or self.session.closed:
                    raise StreamReset(f"QUIC stream {self.id} reset")
                if self._local_closed:
                    raise StreamClosed("write after close")
                chunk = bytes(mv[:1 << 20])
                ok = _lib.SSL_write_ex(self._s, chunk, len(chunk), ctypes.byref(n))
                if ok != 1:
                    err = _lib.SSL_get_error(self._s, ok)
                    _lib.ERR_clear_error()
                    if err != _SSL_ERROR_WANT_WRITE:
                        raise StreamReset(f"QUIC stream {self.id} write failed")
                    n.value = 0
            mv = mv[n.value:]
            # non-blocking SSL_write_ex only queues data: wake the event loop
            # so it is transmitted now, not at the next timer tick
            self.session._kick()
            if mv:
                if deadline is not None and time.monotonic() > deadline:
                    raise TimeoutError("QUIC write timed out")
                self.session._wait_tick(0.05)

    def close(self):
        """Half-close (FIN): no more writes; the peer may keep sending."""
        with self._io:
            if self._local_closed or self._reset or self._freed:
                return
            self._local_closed = True
            _lib.SSL_stream_conclude(self._s, 0)
            _lib.ERR_clear_error()
        self.session._kick()

    def reset(self):
        with self._io:
            with self._cond:
                if self._reset and self._local_closed:
                    return
                self._reset = True
                self._local_closed = True
                self._cond.notify_all()
            if not self._freed:
                _lib.SSL_stream_reset(self._s, None, 0)
                _lib.ERR_clear_error()
        self.session._kick()

    @property
    def remote_peer(self):
        return self.session.remote_peer

    def __repr__(self):
        return f"<QuicStream {self.id} {self.protocol}>"


class _Reactor:
    """One thread drives every QUIC connection.

    It waits (epoll/kqueue via ``selectors``) on all connections' UDP sockets
    plus a single wake-up pipe, and services only the connections that have
    packets, a due timer, or work queued by another thread. Each connection
    therefore costs one file descriptor and no thread of its own."""

    MAX_WAIT = 0.25

    def __init__(self):
        self._sel = selectors.DefaultSelector()
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        self._sel.register(self._wake_r, selectors.EVENT_READ, None)
        self._lock = threading.Lock()
        self._sessions = set()
        self._adding = []
        self._kicked = set()
        self._tick = threading.Condition()
        self._thread = None

    def add(self, sess):
        with self._lock:
            self._adding.append(sess)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True, name="quic-reactor")
                self._thread.start()
        self.wake()

    def kick(self, sess):
        with self._lock:
            self._kicked.add(sess)
        self.wake()

    def wake(self):
        try:
            os.write(self._wake_w, b"\0")
        except (BlockingIOError, OSError):
            pass  # pipe full: a wake-up is already pending

    def wait_tick(self, timeout):
        with self._tick:
            self._tick.wait(timeout)

    def in_reactor(self):
        return threading.current_thread() is self._thread

    def _run(self):
        work = _Work()
        ready = set()
        while True:
            with self._lock:
                adding, self._adding = self._adding, []
                kicked, self._kicked = self._kicked, set()
            for s in adding:
                try:
                    self._sel.register(s._sock, selectors.EVENT_READ, s)
                    self._sessions.add(s)
                    kicked.add(s)
                except (ValueError, OSError):  # socket already closed
                    s._teardown(work)
            now = time.monotonic()
            due = ready | kicked | {s for s in self._sessions if s._deadline <= now}
            for s in due:
                if s in self._sessions and not s._service(work):
                    try:
                        self._sel.unregister(s._sock)
                    except (KeyError, ValueError, OSError):
                        pass
                    self._sessions.discard(s)
                    s._teardown(work)
            with self._tick:
                self._tick.notify_all()
            now = time.monotonic()
            nearest = min((s._deadline for s in self._sessions), default=now + self.MAX_WAIT)
            timeout = max(0.0, min(self.MAX_WAIT, nearest - now))
            ready = set()
            try:
                events = self._sel.select(timeout)
            except OSError:
                events = []
            for key, _ in events:
                if key.data is None:
                    try:
                        while os.read(self._wake_r, 4096):
                            pass
                    except BlockingIOError:
                        pass
                else:
                    ready.add(key.data)


class _Work:
    """Scratch buffers reused by the reactor."""

    def __init__(self):
        self.buf = ctypes.create_string_buffer(65536)
        self.n = _SZ()
        self.tv = _Timeval()
        self.infinite = _I()
        self.close_info = ctypes.create_string_buffer(256)


_reactor = None
_reactor_lock = threading.Lock()


def _get_reactor():
    global _reactor
    with _reactor_lock:
        if _reactor is None:
            _reactor = _Reactor()
        return _reactor


class QuicSession:
    """A libp2p QUIC connection, serviced by the shared reactor. Provides the
    attributes ``Connection`` expects from both the secure channel and the
    muxer session."""

    def __init__(self, ssl_conn, sock, remote_key, local_addr):
        self._c = ssl_conn
        self._sock = sock
        self.remote_key = remote_key
        self.remote_peer = remote_key.peer_id()
        self.local_addr = local_addr
        self.closed = False
        self._closing = False
        self._streams = []
        self._lock = threading.Lock()
        self._deadline = 0.0
        self._done = threading.Event()
        self._reactor = _get_reactor()
        self.on_stream = None
        self.on_close = None
        self._started = False

    def start(self, on_stream, on_close):
        self.on_stream, self.on_close = on_stream, on_close
        self._started = True
        self._reactor.add(self)

    # ---- helpers for other threads ---------------------------------------------
    def _kick(self):
        self._reactor.kick(self)

    def _wait_tick(self, timeout):
        self._reactor.wait_tick(timeout)

    def open_stream(self):
        with self._lock:
            if self.closed or self._closing:
                raise ConnectionError("QUIC connection closed")
            s = _lib.SSL_new_stream(self._c, _STREAM_FLAG_NO_BLOCK)
            if not s:
                msg = _lib.error()
                raise ConnectionError(f"could not open QUIC stream: {msg}")
            st = QuicStream(self, s)
            self._streams.append(st)
        self._kick()
        return st

    def num_streams(self):
        return len(self._streams)

    def ping(self, timeout=10.0):
        # quic-go peers send QUIC keep-alive PINGs; report liveness
        return not self.closed

    def close(self):
        with self._lock:
            if self.closed or self._closing:
                return
            self._closing = True
        if not self._started:
            self._teardown(_Work())  # never handed to the reactor
            return
        self._kick()
        if not self._reactor.in_reactor():
            self._done.wait(timeout=5)

    # ---- called by the reactor ------------------------------------------------
    def _service(self, w):
        """Process events for this connection. Returns False once it is over."""
        L = _lib
        try:
            with self._lock:
                if self._closing:
                    return False
                L.SSL_handle_events(self._c)
                L.ERR_clear_error()
                while True:  # peer-initiated streams
                    s = L.SSL_accept_stream(self._c, _ACCEPT_STREAM_NO_BLOCK)
                    if not s:
                        L.ERR_clear_error()
                        break
                    st = QuicStream(self, s)
                    self._streams.append(st)
                    if self.on_stream:
                        threading.Thread(target=self.on_stream, args=(st,), daemon=True,
                                         name="quic-inbound").start()
                    else:
                        st.reset()
                streams = list(self._streams)
            for st in streams:
                st._pump(w.buf, w.n)
            with self._lock:
                for st in [s for s in self._streams if s._freeable()]:
                    st._free()
                    self._streams.remove(st)
                # OpenSSL writes the close details into the buffer (never NULL)
                if L.SSL_get_conn_close_info(self._c, w.close_info, ctypes.sizeof(w.close_info)) == 1:
                    return False  # closed by the peer or idle timeout
                if L.SSL_get_event_timeout(self._c, ctypes.byref(w.tv), ctypes.byref(w.infinite)) == 1 \
                        and not w.infinite.value:
                    self._deadline = time.monotonic() + w.tv.tv_sec + w.tv.tv_usec / 1e6
                else:
                    self._deadline = time.monotonic() + _Reactor.MAX_WAIT * 20
            return True
        except Exception:
            log.exception("QUIC connection processing failed")
            return False

    def _teardown(self, w=None):
        L = _lib
        with self._lock:
            already = self.closed
            self.closed = True
            streams, self._streams = self._streams, []
            if not already and self._c is not None:
                L.SSL_shutdown_ex(self._c, _SHUTDOWN_FLAG_RAPID | _SHUTDOWN_FLAG_NO_BLOCK, None, 0)
                L.SSL_handle_events(self._c)
                L.ERR_clear_error()
            for st in streams:
                st._free()   # takes each stream's _io: waits out any in-flight call
            c, self._c = self._c, None
            if c is not None:
                L.SSL_free(c)
        try:
            self._sock.close()
        except OSError:
            pass
        self._done.set()
        self._reactor.wake()  # writers waiting on a tick notice the close
        cb, self.on_close = self.on_close, None
        if cb and not already:
            # callbacks may do network I/O: never run them on the reactor thread
            threading.Thread(target=self._run_close_cb, args=(cb,), daemon=True).start()

    def _run_close_cb(self, cb):
        try:
            cb(self)
        except Exception:
            log.exception("QUIC close callback failed")


# ---------------------------------------------------------------------------
# dialing
# ---------------------------------------------------------------------------
def quic_target(ma):
    """(host, port) for ``/ip4|ip6|dns*/<host>/udp/<port>/quic-v1``, else None."""
    ma = Multiaddr(ma).decapsulate_p2p()[0]
    protos = ma.protocols()
    if (len(protos) == 3 and protos[0] in ("ip4", "ip6", "dns", "dns4", "dns6")
            and protos[1] == "udp" and protos[2] == "quic-v1"):
        return ma.parts[0][1], int(ma.parts[1][1])
    return None


def dialable(ma):
    return AVAILABLE and quic_target(ma) is not None


def dial(identity, ma, expected_peer=None, timeout=10.0):
    """Connect to ``ma`` (``.../udp/<port>/quic-v1``). Returns a QuicSession
    whose peer has been authenticated per the libp2p TLS spec."""
    if not AVAILABLE:
        raise OSError(f"QUIC unavailable: {ERROR}")
    L = _lib
    host, port = quic_target(ma)
    proto = Multiaddr(ma).protocols()[0]
    fam = {"ip4": socket.AF_INET, "ip6": socket.AF_INET6, "dns4": socket.AF_INET,
           "dns6": socket.AF_INET6}.get(proto, 0)
    family, _, _, _, sa = socket.getaddrinfo(host, port, fam, socket.SOCK_DGRAM)[0]
    ip = ipaddress.ip_address(sa[0].split("%")[0])
    ctx = _context(identity)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)  # OpenSSL QUIC does non-blocking network I/O itself
    sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
    conn = L.SSL_new(ctx.ctx)
    ok = False
    poller = None
    try:
        if not conn:
            raise OSError(L.error())
        bio = L.BIO_new_dgram(sock.fileno(), 0)
        if not bio:
            raise OSError(L.error())
        L.SSL_set_bio(conn, bio, bio)
        addr = L.BIO_ADDR_new()
        try:
            if (L.BIO_ADDR_rawmake(addr, family, ip.packed, len(ip.packed), socket.htons(port)) != 1
                    or L.SSL_set1_initial_peer_addr(conn, addr) != 1):
                raise OSError(L.error())
        finally:
            L.BIO_ADDR_free(addr)
        if (L.SSL_set_default_stream_mode(conn, _DEFAULT_STREAM_MODE_NONE) != 1
                or L.SSL_set_incoming_stream_policy(conn, _INCOMING_STREAM_POLICY_ACCEPT, 0) != 1):
            raise OSError(L.error())
        # handshake in non-blocking mode so the dial timeout is honoured;
        # selectors (epoll) rather than select(), which fails above fd 1024
        L.SSL_set_blocking_mode(conn, 0)
        poller = selectors.DefaultSelector()
        poller.register(sock, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while True:
            r = L.SSL_connect(conn)
            if r == 1:
                break
            err = L.SSL_get_error(conn, r)
            if err not in (_SSL_ERROR_WANT_READ, _SSL_ERROR_WANT_WRITE):
                raise OSError(f"QUIC handshake failed: {L.error()}")
            if time.monotonic() > deadline:
                raise TimeoutError("QUIC handshake timed out")
            L.SSL_handle_events(conn)
            tv, inf = _Timeval(), _I()
            wait = 0.05
            if L.SSL_get_event_timeout(conn, ctypes.byref(tv), ctypes.byref(inf)) == 1 and not inf.value:
                wait = min(wait, tv.tv_sec + tv.tv_usec / 1e6)
            poller.select(max(0.0, min(wait, deadline - time.monotonic())))
        poller.close()
        poller = None
        remote_key = _verify_peer(conn)
        if expected_peer is not None and remote_key.peer_id() != expected_peer:
            raise OSError(f"peer ID mismatch: expected {expected_peer}, got {remote_key.peer_id()}")
        local = sock.getsockname()
        local_ip = ipaddress.ip_address(local[0].split("%")[0])
        local_ma = Multiaddr(f"/ip{local_ip.version}/{local_ip}/udp/{local[1]}/quic-v1")
        ok = True
        return QuicSession(conn, sock, remote_key, local_ma)
    finally:
        if poller is not None:
            poller.close()
        if not ok:
            L.ERR_clear_error()
            if conn:
                L.SSL_shutdown_ex(conn, _SHUTDOWN_FLAG_RAPID, None, 0)
                L.SSL_free(conn)
            sock.close()


def _verify_peer(conn):
    L = _lib
    alpn, alen = _P(), ctypes.c_uint()
    L.SSL_get0_alpn_selected(conn, ctypes.byref(alpn), ctypes.byref(alen))
    if ctypes.string_at(alpn, alen.value) != ALPN:
        raise OSError("peer did not negotiate ALPN 'libp2p'")
    chain = L.SSL_get_peer_cert_chain(conn)
    if not chain or L.OPENSSL_sk_num(chain) != 1:
        raise OSError("peer must present exactly one certificate")
    x = L.SSL_get1_peer_certificate(conn)
    if not x:
        raise OSError("peer presented no certificate")
    try:
        if L.X509_verify(x, L.X509_get0_pubkey(x)) != 1:
            L.ERR_clear_error()
            raise OSError("peer certificate is not validly self-signed")
        der = _i2d(L.i2d_X509, x)
    finally:
        L.X509_free(x)
    try:
        return verify_certificate(der)
    except (ValueError, IndexError) as e:
        raise OSError(f"invalid libp2p certificate: {e}") from None


_load()
