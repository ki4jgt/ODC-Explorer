"""Yamux stream multiplexer (/yamux/1.0.0), thread based.

Spec: https://github.com/hashicorp/yamux/blob/master/spec.md
"""

import itertools
import logging
import struct
import threading

PROTOCOL_ID = "/yamux/1.0.0"

DATA, WINDOW_UPDATE, PING, GO_AWAY = 0, 1, 2, 3
SYN, ACK, FIN, RST = 1, 2, 4, 8
INITIAL_WINDOW = 256 * 1024
RECV_WINDOW = 4 * 1024 * 1024
MAX_FRAME_PAYLOAD = 256 * 1024
_HDR = struct.Struct(">BBHII")

log = logging.getLogger(__name__)


class StreamReset(ConnectionError):
    pass


class StreamClosed(EOFError):
    pass


class YamuxStream:
    def __init__(self, session, sid):
        self.session = session
        self.id = sid
        self.protocol = None
        self._cond = threading.Condition()
        self._buf = bytearray()
        self._send_window = INITIAL_WINDOW
        self._recv_window = INITIAL_WINDOW
        self._consumed = 0
        self._remote_closed = False
        self._local_closed = False
        self._reset = False

    # ---- called by the session reader --------------------------------
    def _on_data(self, data):
        with self._cond:
            if len(data) > self._recv_window:
                log.warning("yamux: peer exceeded receive window on stream %d", self.id)
            self._recv_window -= len(data)
            self._buf += data
            self._cond.notify_all()

    def _on_window(self, delta):
        with self._cond:
            self._send_window += delta
            self._cond.notify_all()

    def _on_flags(self, flags):
        with self._cond:
            if flags & FIN:
                self._remote_closed = True
            if flags & RST:
                self._reset = True
            self._cond.notify_all()
        if self._remote_closed and self._local_closed or self._reset:
            self.session._forget(self.id)

    # ---- reading -----------------------------------------------------
    def _take(self, n):
        out = bytes(self._buf[:n])
        del self._buf[:n]
        self._consumed += len(out)
        if self._consumed >= RECV_WINDOW // 2 and not self._reset:
            delta, self._consumed = self._consumed, 0
            self._recv_window += delta
            self.session._send_frame(WINDOW_UPDATE, 0, self.id, delta)
        return out

    def read(self, n: int = -1, timeout=None) -> bytes:
        """Read up to ``n`` bytes (any available if n < 0). Returns b'' at EOF."""
        with self._cond:
            while not self._buf:
                if self._reset:
                    raise StreamReset(f"stream {self.id} reset")
                if self._remote_closed:
                    return b""
                if not self._cond.wait(timeout):
                    raise TimeoutError("yamux read timed out")
            return self._take(len(self._buf) if n < 0 else n)

    def read_exact(self, n: int, timeout=None) -> bytes:
        with self._cond:
            while len(self._buf) < n:
                if self._reset:
                    raise StreamReset(f"stream {self.id} reset")
                if self._remote_closed:
                    raise StreamClosed("stream closed by peer")
                if not self._cond.wait(timeout):
                    raise TimeoutError("yamux read timed out")
            return self._take(n)

    def read_all(self, timeout=None) -> bytes:
        out = bytearray()
        while True:
            chunk = self.read(timeout=timeout)
            if not chunk:
                return bytes(out)
            out += chunk

    # ---- writing -----------------------------------------------------
    def write(self, data: bytes, timeout=None):
        mv = memoryview(bytes(data))
        while mv:
            with self._cond:
                while self._send_window <= 0:
                    if self._reset:
                        raise StreamReset(f"stream {self.id} reset")
                    if not self._cond.wait(timeout):
                        raise TimeoutError("yamux send window never opened")
                if self._reset:
                    raise StreamReset(f"stream {self.id} reset")
                if self._local_closed:
                    raise StreamClosed("write after close")
                n = min(len(mv), self._send_window, MAX_FRAME_PAYLOAD)
                self._send_window -= n
            self.session._send_frame(DATA, 0, self.id, n, bytes(mv[:n]))
            mv = mv[n:]

    def close(self):
        """Half-close: we will send no more data (peer may still send)."""
        with self._cond:
            if self._local_closed or self._reset:
                return
            self._local_closed = True
        try:
            self.session._send_frame(WINDOW_UPDATE, FIN, self.id, 0)
        except OSError:
            pass
        if self._remote_closed:
            self.session._forget(self.id)

    def reset(self):
        with self._cond:
            if self._reset:
                return
            self._reset = True
            self._cond.notify_all()
        try:
            self.session._send_frame(WINDOW_UPDATE, RST, self.id, 0)
        except OSError:
            pass
        self.session._forget(self.id)

    @property
    def remote_peer(self):
        return self.session.conn.remote_peer

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close() if exc[0] is None else self.reset()

    def __repr__(self):
        return f"<YamuxStream {self.id} {self.protocol}>"


class YamuxSession:
    def __init__(self, conn, is_client: bool, on_stream=None, on_close=None):
        self.conn = conn
        self.is_client = is_client
        self.on_stream = on_stream
        self.on_close = on_close
        self._ids = itertools.count(1 if is_client else 2, 2)
        self._streams = {}
        self._lock = threading.Lock()
        self._pings = {}
        self._ping_ids = itertools.count(1)
        self.closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True, name="yamux-reader")
        self._reader.start()

    def _send_frame(self, ftype, flags, sid, length, payload=b""):
        if self.closed:
            raise ConnectionError("yamux session closed")
        self.conn.write(_HDR.pack(0, ftype, flags, sid, length) + payload)

    def open_stream(self) -> YamuxStream:
        with self._lock:
            if self.closed:
                raise ConnectionError("yamux session closed")
            sid = next(self._ids)
            st = YamuxStream(self, sid)
            st._recv_window = RECV_WINDOW
            self._streams[sid] = st
        self._send_frame(WINDOW_UPDATE, SYN, sid, RECV_WINDOW - INITIAL_WINDOW)
        return st

    def ping(self, timeout=10.0) -> bool:
        pid = next(self._ping_ids) & 0xFFFFFFFF
        ev = threading.Event()
        self._pings[pid] = ev
        self._send_frame(PING, SYN, 0, pid)
        ok = ev.wait(timeout)
        self._pings.pop(pid, None)
        return ok

    def _forget(self, sid):
        with self._lock:
            self._streams.pop(sid, None)

    def num_streams(self):
        return len(self._streams)

    def _read_loop(self):
        try:
            while True:
                ver, ftype, flags, sid, length = _HDR.unpack(self.conn.read_exact(12))
                if ver != 0:
                    raise ConnectionError(f"bad yamux version {ver}")
                if ftype == PING:
                    if flags & SYN:
                        self._send_frame(PING, ACK, 0, length)
                    elif flags & ACK and length in self._pings:
                        self._pings[length].set()
                    continue
                if ftype == GO_AWAY:
                    break
                payload = self.conn.read_exact(length) if ftype == DATA and length else b""
                st = self._streams.get(sid)
                if st is None and flags & SYN:
                    st = YamuxStream(self, sid)
                    st._recv_window = RECV_WINDOW
                    with self._lock:
                        self._streams[sid] = st
                    self._send_frame(WINDOW_UPDATE, ACK, sid, RECV_WINDOW - INITIAL_WINDOW)
                    if self.on_stream:
                        threading.Thread(target=self.on_stream, args=(st,), daemon=True,
                                         name="yamux-inbound").start()
                    else:
                        st.reset()
                if st is None:
                    if not flags & RST and ftype == DATA and length:
                        self._send_frame(WINDOW_UPDATE, RST, sid, 0)
                    continue
                if ftype == WINDOW_UPDATE:
                    st._on_window(length)
                elif payload:
                    st._on_data(payload)
                if flags & (FIN | RST):
                    st._on_flags(flags)
        except (EOFError, OSError, ConnectionError, ValueError) as e:
            log.debug("yamux session ended: %s", e)
        except Exception:
            log.exception("yamux reader crashed")
        finally:
            self._shutdown()

    def _shutdown(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True
            streams = list(self._streams.values())
            self._streams.clear()
        for st in streams:
            with st._cond:
                st._reset = True
                st._cond.notify_all()
        for ev in self._pings.values():
            ev.set()
        try:
            self.conn.close()
        except OSError:
            pass
        if self.on_close:
            self.on_close(self)

    def close(self):
        if not self.closed:
            try:
                self._send_frame(GO_AWAY, 0, 0, 0)
            except (OSError, ConnectionError):
                pass
        self._shutdown()
