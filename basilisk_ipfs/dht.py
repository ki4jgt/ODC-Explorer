"""Kademlia DHT client (libp2p kad-dht, /ipfs/kad/1.0.0).

Supports FIND_NODE, GET_PROVIDERS, ADD_PROVIDER, GET_VALUE and PUT_VALUE with
iterative, parallel lookups. Runs in client mode (it does not answer queries).
"""

import hashlib
import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import protobuf as pb
from .cid import CID
from .keys import PeerID
from .multiaddr import Multiaddr
from .p2p.host import dialable, read_delimited, write_delimited

log = logging.getLogger(__name__)

PROTOCOL = "/ipfs/kad/1.0.0"
LAN_PROTOCOL = "/ipfs/lan/kad/1.0.0"
PUT_VALUE, GET_VALUE, ADD_PROVIDER, GET_PROVIDERS, FIND_NODE, PING = 0, 1, 2, 3, 4, 5
K = 20
ALPHA = 10

BOOTSTRAP = [
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
]


class DHTMessage:
    def __init__(self, type, key=b"", record=None, closer=None, providers=None):
        self.type = type
        self.key = key
        self.record = record  # (key, value) or None
        self.closer = closer or []        # [(PeerID, [Multiaddr])]
        self.providers = providers or []  # [(PeerID, [Multiaddr])]

    @staticmethod
    def _enc_peer(pid, addrs):
        return pb.enc_bytes(1, pid.to_bytes()) + b"".join(pb.enc_bytes(2, Multiaddr(a).to_bytes()) for a in addrs)

    def encode(self) -> bytes:
        out = pb.enc_varint(1, self.type)
        if self.key:
            out += pb.enc_bytes(2, self.key)
        if self.record is not None:
            out += pb.enc_bytes(3, pb.enc_bytes(1, self.record[0]) + pb.enc_bytes(2, self.record[1]))
        for pid, addrs in self.closer:
            out += pb.enc_bytes(8, self._enc_peer(pid, addrs))
        for pid, addrs in self.providers:
            out += pb.enc_bytes(9, self._enc_peer(pid, addrs))
        return out

    @staticmethod
    def _dec_peers(raws):
        out = []
        for raw in raws:
            p = pb.decode(raw)
            try:
                pid = PeerID(pb.first(p, 1))
            except Exception:
                continue
            addrs = []
            for a in p.get(2, []):
                try:
                    addrs.append(Multiaddr(a))
                except (ValueError, IndexError):
                    pass
            out.append((pid, addrs))
        return out

    @classmethod
    def decode(cls, buf):
        m = pb.decode(buf)
        rec = None
        if 3 in m:
            r = pb.decode(m[3][0])
            rec = (pb.first(r, 1, b""), pb.first(r, 2, b""))
        return cls(pb.first(m, 1, 0), pb.first(m, 2, b""), rec,
                   cls._dec_peers(m.get(8, [])), cls._dec_peers(m.get(9, [])))


def _dist(a: bytes, b: bytes) -> int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


class DHT:
    def __init__(self, host, bootstrap=None, protocol=PROTOCOL, rpc_timeout=10.0):
        self.host = host
        self.protocol = protocol
        self.bootstrap_addrs = BOOTSTRAP if bootstrap is None else list(bootstrap)
        self.rpc_timeout = rpc_timeout
        self.table = {}  # PeerID -> last seen; addresses live in host.peerstore
        self._lock = threading.Lock()
        host.on_connect(self._on_connect)

    def _on_connect(self, conn):
        # identify runs asynchronously; peers that speak kad get added on use
        pass

    def add_peer(self, pid, addrs=()):
        if pid == self.host.peer_id:
            return
        self.host.add_addrs(pid, addrs)
        with self._lock:
            self.table[pid] = time.time()
        if self.host.connmgr is not None:
            self.host.connmgr.tag_peer(pid, "dht", 1)

    # ---- bootstrap -------------------------------------------------------
    def bootstrap(self, wait_refresh=False):
        from .dns import resolve_dnsaddr
        addrs = []
        for a in self.bootstrap_addrs:
            try:
                addrs.extend(resolve_dnsaddr(a))
            except OSError as e:
                log.debug("dnsaddr %s failed: %s", a, e)
        by_peer = {}
        for a in addrs:
            pid = a.peer_id
            if pid is not None:
                by_peer.setdefault(pid, []).append(a)

        def dial(item):
            pid, alist = item
            self.host.connect_peer(pid, alist)
            self.add_peer(pid, alist)
            return pid

        ok = 0
        ex = ThreadPoolExecutor(8)
        futures = [ex.submit(dial, it) for it in by_peer.items()]
        try:
            for f in as_completed(futures, timeout=self.host.dial_timeout + 2):
                try:
                    f.result()
                    ok += 1
                    if ok >= min(3, len(futures)):
                        break
                except Exception as e:
                    log.debug("bootstrap dial failed: %s", e)
        except TimeoutError:
            pass
        ex.shutdown(wait=False)
        if ok:
            # populate the routing table in the background
            def refresh():
                try:
                    self.find_closest_peers(self.host.peer_id.to_bytes(), timeout=30)
                except Exception as e:
                    log.debug("self lookup failed: %s", e)
            if wait_refresh:
                refresh()
            else:
                threading.Thread(target=refresh, daemon=True).start()
        return ok

    # ---- rpc -------------------------------------------------------------
    def _rpc(self, peer, msg: DHTMessage, expect_reply=True):
        st = self.host.new_stream(peer, self.protocol, timeout=self.rpc_timeout)
        try:
            write_delimited(st, msg.encode())
            if not expect_reply:
                st.close()
                return None
            resp = DHTMessage.decode(read_delimited(st, timeout=self.rpc_timeout))
            st.close()
            return resp
        except Exception:
            st.reset()
            raise

    # ---- iterative lookup ------------------------------------------------
    def _lookup(self, key: bytes, msg_type, on_response=None, count=K, timeout=60.0):
        """Iterative Kademlia lookup. Terminates when the ``count`` closest
        known peers have all answered, ``on_response`` returns True, or time
        runs out. Returns the closest responsive peers."""
        target = hashlib.sha256(key).digest()
        deadline = time.monotonic() + timeout
        with self._lock:
            candidates = set(self.table)
        candidates |= {p for p in self.host.peers()
                       if self.protocol in self.host.peer_info(p).protocols}
        candidates.discard(self.host.peer_id)
        queried, responded, failed = set(), set(), set()
        results = queue.Queue()
        inflight = 0
        msg = DHTMessage(msg_type, key)

        def worker(p):
            try:
                results.put((p, self._rpc(p, msg), None))
            except Exception as e:
                results.put((p, None, e))

        def ranked():
            return sorted(candidates - failed, key=lambda p: _dist(p.dht_key(), target))

        while time.monotonic() < deadline:
            order = ranked()
            top = order[:count]
            if top and all(p in responded for p in top):
                break
            for p in order:
                if inflight >= ALPHA:
                    break
                if p not in queried:
                    queried.add(p)
                    inflight += 1
                    threading.Thread(target=worker, args=(p,), daemon=True).start()
            if inflight == 0:
                break
            try:
                p, resp, err = results.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                break
            inflight -= 1
            if err is not None:
                log.debug("dht query to %s failed: %s", p, err)
                failed.add(p)
                with self._lock:
                    self.table.pop(p, None)
                continue
            responded.add(p)
            self.add_peer(p)
            for pid, addrs in resp.closer:
                if pid != self.host.peer_id:
                    self.host.add_addrs(pid, addrs)
                    if self.host.is_connected(pid) or any(dialable(a) for a in addrs):
                        candidates.add(pid)
            if on_response and on_response(p, resp):
                break
        return [p for p in ranked() if p in responded][:count]

    def find_closest_peers(self, key: bytes, count=K, timeout=60.0):
        return self._lookup(key, FIND_NODE, count=count, timeout=timeout)

    def find_peer(self, peer, timeout=60.0):
        """Return known multiaddrs for ``peer``."""
        peer = PeerID.decode(peer)
        found = []

        def on_resp(_, resp):
            for pid, addrs in resp.closer:
                if pid == peer and addrs:
                    found.extend(addrs)
                    return True
            return False

        self._lookup(peer.to_bytes(), FIND_NODE, on_resp, timeout=timeout)
        return list(dict.fromkeys(found)) or list(self.host.peer_info(peer).addrs)

    def find_providers(self, cid, count=20, timeout=60.0, callback=None):
        """Return ``[(PeerID, [Multiaddr])]`` of peers announcing ``cid``.
        ``callback(peer, addrs)`` is called for each provider as soon as it is
        found, so callers can start connecting while the lookup continues."""
        key = CID.decode(cid).multihash
        found = {}

        def on_resp(_, resp):
            for pid, addrs in resp.providers:
                self.host.add_addrs(pid, addrs)
                new = pid not in found
                found.setdefault(pid, []).extend(addrs)
                if new and callback is not None:
                    try:
                        callback(pid, addrs)
                    except Exception:
                        log.exception("provider callback failed")
            return len(found) >= count

        self._lookup(key, GET_PROVIDERS, on_resp, timeout=timeout)
        return list(found.items())

    def provide(self, cid, timeout=60.0):
        """Announce that we can serve ``cid`` (requires a publicly dialable listen address)."""
        key = CID.decode(cid).multihash
        peers = self.find_closest_peers(key, timeout=timeout)
        me = (self.host.peer_id, self.host.addrs())
        msg = DHTMessage(ADD_PROVIDER, key, providers=[me])
        sent = 0
        for p in peers:
            try:
                self._rpc(p, msg, expect_reply=False)
                sent += 1
            except Exception as e:
                log.debug("ADD_PROVIDER to %s failed: %s", p, e)
        return sent

    def get_values(self, key: bytes, validator=None, quorum=8, timeout=60.0):
        """Collect records for ``key`` from the closest peers."""
        values = []

        def on_resp(p, resp):
            if resp.record and resp.record[1]:
                v = resp.record[1]
                if validator is None or validator(key, v):
                    values.append((p, v))
            return len(values) >= quorum

        self._lookup(key, GET_VALUE, on_resp, timeout=timeout)
        return values

    def put_value(self, key: bytes, value: bytes, timeout=60.0):
        peers = self.find_closest_peers(key, timeout=timeout)
        msg = DHTMessage(PUT_VALUE, key, record=(key, value))
        ok = 0
        for p in peers:
            try:
                self._rpc(p, msg)
                ok += 1
            except Exception as e:
                log.debug("PUT_VALUE to %s failed: %s", p, e)
        return ok
