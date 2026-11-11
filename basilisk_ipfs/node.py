"""High-level IPFS node: a libp2p host + Bitswap + (optional) DHT over a local
blockstore, with UnixFS import/export, pinning, GC and IPNS."""

import datetime
import json
import logging
import os
import threading
import time

from . import dagcbor, ipns, unixfs
from .bitswap import Bitswap, BlockUnavailable
from .blockstore import BlockNotFound, FilesystemBlockstore, MemoryBlockstore, StorageFull
from .storage import ManagedBlockstore
from .cid import CID
from .dagpb import PBNode
from .keys import Ed25519PrivateKey, PeerID
from .multiaddr import Multiaddr
from .p2p.host import Host

log = logging.getLogger(__name__)


class _Fetcher:
    """Block getter used by the exporter: local store first, then the network
    (connected peers via Bitswap -> DHT providers -> HTTP gateways)."""

    PROVIDER_SEARCH_DELAY = 1.0  # boxo/bitswap's default

    def __init__(self, node, timeout):
        self.node = node
        self.timeout = timeout

    def get(self, cid):
        cid = CID.decode(cid)
        return self.get_many([cid])[cid]

    def get_many(self, cids):
        node = self.node
        out, missing = {}, []
        for c in cids:
            c = CID.decode(c)
            if c.codec == 0x00 or c.hash_code == 0x00:  # identity CID: data is inline
                out[c] = c.digest
                continue
            try:
                out[c] = node.blockstore.get(c)
            except BlockNotFound:
                missing.append(c)
        if not missing:
            return out
        if node.offline:
            raise BlockNotFound(f"{missing[0]} not in local blockstore (offline)")
        # Like Kubo's Bitswap: ask connected peers, and if nothing arrives
        # within PROVIDER_SEARCH_DELAY start a DHT provider search in parallel,
        # connecting to providers as they are found (newly connected peers are
        # sent our wantlist automatically).
        done = threading.Event()
        if node.dht is not None:
            def search():
                if not done.wait(self.PROVIDER_SEARCH_DELAY):
                    node._connect_providers(missing[0])
            threading.Thread(target=search, daemon=True, name="provider-search").start()
        timeout = min(self.timeout, 30.0) if node.gateways else self.timeout
        try:
            out.update(node.bitswap.get_many(missing, timeout=timeout, rebroadcast=2.0))
            return out
        except BlockUnavailable:
            pass
        finally:
            done.set()
        for c in missing:
            if c in out:
                continue
            try:
                out[c] = node.blockstore.get(c)
                continue
            except BlockNotFound:
                pass
            for gw in node.gateways:
                try:
                    data = gw.get_block(c)
                    node.blockstore.put(c, data, verify=False)
                    out[c] = data
                    break
                except Exception as e:
                    log.debug("gateway %s failed for %s: %s", gw.base, c, e)
            else:
                raise BlockUnavailable(f"could not retrieve {c}")
        return out


class IPFSNode:
    """An embeddable IPFS node.

    :param repo: directory for blocks, identity key and pins; ``None`` keeps
        everything in memory with a fresh identity.
    :param listen: multiaddrs to accept libp2p connections on (``[]`` to only dial).
    :param peers: multiaddrs (with ``/p2p/<id>``) to connect to on start.
    :param dht: ``True`` to use the public Kademlia DHT for routing,
        ``"lan"`` for the LAN DHT, or ``False``.
    :param bootstrap: DHT bootstrap multiaddrs (default: the public list).
    :param gateways: URLs of trustless HTTP gateways used as a fallback.
    :param offline: never touch the network.
    :param storage_max: limit on stored block data, as bytes or a string like
        ``"10GB"``. When usage passes ``gc_high_water`` (default 90%) of it,
        the least recently used unpinned blocks are deleted until usage is
        under ``gc_low_water`` (default 80%). Imports, ``block_put`` and
        ``pin_add`` raise ``StorageFull`` rather than exceed the limit.
    :param announce: announce exactly these multiaddrs (Kubo ``Addresses.Announce``).
    :param append_announce: extra multiaddrs to announce (``Addresses.AppendAnnounce``).
    :param no_announce: multiaddrs/CIDRs never to announce (``Addresses.NoAnnounce``).
    :param nat_port_map: map listen ports on the router via UPnP / NAT-PMP
        (Kubo's default; ``False`` = ``Swarm.DisableNatPortMap``).
    :param autonat: verify which public addresses are reachable (AutoNAT v2).
    :param autonat_service: answer other peers' AutoNAT v2 dial requests.
    :param relay_client: Circuit Relay v2 client (Kubo ``Swarm.RelayClient``):
        when AutoNAT finds we are not publicly reachable, reserve slots on
        public relays and announce ``/p2p-circuit`` addresses; also lets us
        dial peers that are only reachable through relays. ``"always"``
        reserves regardless of reachability.
    :param static_relays: relay multiaddrs to use instead of automatic choice.
    :param relay_service: act as a relay for others (``Swarm.RelayService``).
    :param hole_punching: upgrade relayed connections to direct ones with
        DCUtR (``Swarm.EnableHolePunching``).
    :param provide_strategy: what to announce to the DHT and keep re-announcing
        (Kubo ``Provide.Strategy``): ``"all"`` blocks (default), ``"pinned"``,
        ``"roots"``, or ``None`` to never announce. Needs ``dht``.
    :param reprovide_interval: seconds between re-announcements (22 h, as Kubo).
    :param ipns_republish_period: seconds between IPNS republishes (4 h, as Kubo).
    :param conn_low_water, conn_high_water, conn_grace_period: connection
        manager limits (Kubo ``Swarm.ConnMgr``: 32 / 96 / 20 s). Above the high
        water mark the least valuable connections are closed down to the low
        water mark. ``conn_high_water=None`` disables trimming.
    :param fd_limit: raise the process's soft open-file limit to this (Kubo's
        ``IPFS_FD_MAX``, 8192) when the hard limit allows; ``None`` leaves it.
    """

    def __init__(self, repo=None, *, identity=None, listen=("/ip4/0.0.0.0/tcp/0",), peers=(),
                 dht=False, bootstrap=None, gateways=(), offline=False, fetch_timeout=60.0,
                 storage_max=None, gc_high_water=0.9, gc_low_water=0.8,
                 announce=None, append_announce=(), no_announce=(), nat_port_map=True,
                 autonat=True, autonat_service=False, relay_client=True, static_relays=(),
                 relay_service=False, hole_punching=True, provide_strategy="all",
                 reprovide_interval=22 * 3600, ipns_republish_period=4 * 3600,
                 conn_low_water=32, conn_high_water=96, conn_grace_period=20.0,
                 fd_limit=8192):
        self.repo = os.path.abspath(repo) if repo else None
        if self.repo:
            os.makedirs(self.repo, exist_ok=True)
            store = FilesystemBlockstore(os.path.join(self.repo, "blocks"))
            keyfile = os.path.join(self.repo, "identity.key")
            if identity is None:
                if os.path.exists(keyfile):
                    identity = Ed25519PrivateKey.load(keyfile)
                else:
                    identity = Ed25519PrivateKey()
                    identity.save(keyfile)
        else:
            store = MemoryBlockstore()
        self.blockstore = ManagedBlockstore(store, storage_max, self._pinned_multihashes,
                                            gc_high_water, gc_low_water)
        self.identity = identity or Ed25519PrivateKey()
        self.offline = offline
        self.host = Host(self.identity, announce=announce, append_announce=append_announce,
                         no_announce=no_announce)
        self._nat_port_map = nat_port_map and not offline
        self._autonat = autonat and not offline
        self.nat = None
        self.autonat = None
        self.relay = None
        self.relay_service = None
        self.hole_punch = None
        if not offline:
            from .p2p.relay import RelayClient, RelayService
            from .p2p.dcutr import HolePunchService
            if relay_client:
                self.relay = RelayClient(self.host, auto=relay_client, static_relays=static_relays)
            if relay_service:
                self.relay_service = RelayService(self.host)
            if hole_punching:
                self.hole_punch = HolePunchService(self.host)
        if autonat_service and not offline:
            from .p2p.autonat import AutoNATService
            AutoNATService(self.host)
        self._fd_limit = fd_limit
        self.connmgr = None
        if conn_high_water is not None and not offline:
            from .p2p.connmgr import ConnectionManager
            self.connmgr = ConnectionManager(self.host, conn_low_water, conn_high_water,
                                             conn_grace_period)
        self.bitswap = Bitswap(self.host, self.blockstore)
        self.dht = None
        if dht and not offline:
            from .dht import DHT, LAN_PROTOCOL, PROTOCOL
            self.dht = DHT(self.host, bootstrap, LAN_PROTOCOL if dht == "lan" else PROTOCOL)
        from .http_client import GatewayClient
        self.gateways = [g if isinstance(g, GatewayClient) else GatewayClient(g) for g in gateways]
        self._listen = list(listen) if not offline else []
        self._initial_peers = list(peers)
        self.fetcher = _Fetcher(self, fetch_timeout)
        self._pins = self._load_pins()
        self._pin_lock = threading.Lock()
        self._provide_strategy = provide_strategy
        self._reprovide_interval = reprovide_interval
        self._ipns_republish_period = ipns_republish_period
        self.provider = None
        self.ipns_republisher = None
        self._ipns_seq = {}
        self._ipns_keys = {ipns.name_for_key(self.identity.public_key): self.identity}
        self._ipns_published = {}  # name -> {"published": ts, "lifetime": seconds}
        self._local_records = {}
        self._load_ipns()
        self.started = False

    # ---- lifecycle ---------------------------------------------------------
    def start(self):
        if self.started:
            return self
        self.started = True
        for a in self._listen:
            self.host.listen(a)
        listening_publicly = any(not a.tcp_target()[0].startswith("127.") and a.tcp_target()[0] != "::1"
                                 for a in self.host.listen_addrs)
        if listening_publicly and self._nat_port_map:
            from .nat import NATManager
            self.nat = NATManager(self.host)
        if listening_publicly and self._autonat:
            from .p2p.autonat import AutoNATClient
            self.autonat = AutoNATClient(self.host)
        if self._fd_limit:
            from .p2p.connmgr import raise_fd_limit
            raise_fd_limit(self._fd_limit)
        for p in self._initial_peers:
            try:
                conn = self.connect(p)
                if self.connmgr is not None:  # configured peers are never trimmed
                    self.connmgr.protect(conn.remote_peer, "static")
            except Exception as e:
                log.warning("could not connect to %s: %s", p, e)
        if self.dht is not None:
            self.dht.bootstrap()
            self.dht.start_maintenance()
            from .provider import IPNSRepublisher, Provider
            if self._provide_strategy:
                state = os.path.join(self.repo, "provider.sqlite") if self.repo else None
                self.provider = Provider(self, self._provide_strategy, self._reprovide_interval,
                                         state_path=state)
                self.provider.notify()  # announce whatever is due now
            self.ipns_republisher = IPNSRepublisher(self, self._ipns_republish_period)
        return self

    def stop(self):
        if self.provider is not None:
            self.provider.close()
            self.provider = None
        if self.ipns_republisher is not None:
            self.ipns_republisher.close()
            self.ipns_republisher = None
        if self.relay is not None:
            self.relay.close()
        if self.autonat is not None:
            self.autonat.stop()
        if self.nat is not None:
            self.nat.close()  # remove router port mappings
        if self.connmgr is not None:
            self.connmgr.close()
        if self.dht is not None:
            self.dht.stop()
        self.host.close()
        self.started = False

    close = stop

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ---- identity & peers --------------------------------------------------
    @property
    def peer_id(self) -> PeerID:
        return self.host.peer_id

    def id(self) -> dict:
        return {"ID": str(self.peer_id),
                "PublicKey": self.identity.public_key.to_protobuf(),
                "Addresses": [f"{a}/p2p/{self.peer_id}" for a in self.host.addrs()],
                "AgentVersion": "basilisk-ipfs/0.1.0",
                "Reachability": self.host.reachability,
                "Protocols": self.host.protocols()}

    def connect(self, addr):
        return self.host.connect(addr)

    def disconnect(self, peer):
        self.host.disconnect(peer)

    def peers(self):
        return self.host.peers()

    def ping(self, peer, count=3):
        return self.host.ping(peer, count)

    # ---- adding ----------------------------------------------------------
    def _importer(self, **opts):
        return unixfs.Importer(self.blockstore, **opts)

    def _after_add(self, cid, pin, provide):
        if pin:
            self.pin_add(cid, fetch=False)
        if self.started:
            self.bitswap.notify_new_blocks([cid])
        if provide is False:
            return
        if self.provider is not None:
            if provide:  # announce the root right away, whatever the strategy
                threading.Thread(target=self.provider.provide_now, args=([cid],), daemon=True).start()
            self.provider.notify()  # strategy decides what else to announce
        elif provide and self.dht is not None:
            threading.Thread(target=self.dht.provide, args=(cid,), daemon=True).start()

    def add_bytes(self, data: bytes, *, pin=True, provide=None, **opts) -> CID:
        """Import bytes as a UnixFS file. ``opts``: cid_version, raw_leaves,
        chunk_size, hash_fn, max_links (same defaults as ``ipfs add``).
        Raises ``StorageFull`` if the data won't fit under ``storage_max``.
        ``provide``: None = follow ``provide_strategy`` (announced and kept
        announced in the background), True = also announce the root right
        away, False = don't announce now (the reprovider may still, per strategy)."""
        with self.blockstore.session():
            res = self._importer(**opts).add_bytes(data)
            self._after_add(res.cid, pin, provide)
        return res.cid

    def add_stream(self, stream, *, pin=True, provide=None, **opts) -> CID:
        with self.blockstore.session():
            res = self._importer(**opts).add_stream(stream)
            self._after_add(res.cid, pin, provide)
        return res.cid

    def add_path(self, path, *, wrap=False, pin=True, provide=None, include_hidden=False, **opts):
        """Import a file or directory tree. Returns the root ``ImportResult``."""
        with self.blockstore.session():
            imp = self._importer(include_hidden=include_hidden, **opts)
            res = imp.add_path(path)
            if wrap:
                res = imp.wrap([res])
            self._after_add(res.cid, pin, provide)
        return res

    add_file = add_path

    # ---- reading -----------------------------------------------------------
    def resolve(self, path) -> CID:
        """Resolve ``/ipfs/...``, ``/ipns/...`` or ``<cid>/...`` to a CID."""
        path = str(path) if not isinstance(path, CID) else path
        if isinstance(path, str) and path.startswith("/ipns/"):
            rest = path[6:]
            name, _, sub = rest.partition("/")
            target = self.name_resolve(name)
            path = target + ("/" + sub if sub else "")
        return unixfs.resolve(self.fetcher, path)

    def cat(self, path, offset=0, length=None) -> bytes:
        return b"".join(self.cat_stream(path, offset, length))

    def cat_stream(self, path, offset=0, length=None):
        return unixfs.cat(self.fetcher, self.resolve(path), offset, length)

    def ls(self, path):
        return unixfs.ls(self.fetcher, self.resolve(path))

    def stat(self, path) -> dict:
        return unixfs.stat(self.fetcher, self.resolve(path))

    def get(self, path, dest):
        """Download a file or directory to ``dest`` on disk."""
        unixfs.export(self.fetcher, self.resolve(path), dest)
        return dest

    # ---- blocks & DAGs -----------------------------------------------------
    def block_get(self, cid) -> bytes:
        return self.fetcher.get(CID.decode(cid))

    def block_put(self, data: bytes, codec="raw", cid_version=1, hash_fn="sha2-256") -> CID:
        with self.blockstore.session():
            cid = self.blockstore.put_block(data, codec, cid_version, hash_fn)
        if self.started:
            self.bitswap.notify_new_blocks([cid])
        return cid

    def block_has(self, cid) -> bool:
        return self.blockstore.has(cid)

    def block_rm(self, cid):
        self.blockstore.delete(cid)

    def dag_put(self, obj, pin=False) -> CID:
        """Store a Python value as a DAG-CBOR block (CIDs become links)."""
        cid = self.block_put(dagcbor.encode(obj), "dag-cbor")
        if pin:
            self.pin_add(cid, fetch=False)
        return cid

    def dag_get(self, cid):
        """Decode a block: DAG-CBOR -> Python value, DAG-PB -> dict, raw -> bytes."""
        cid = CID.decode(cid) if not isinstance(cid, str) or not cid.startswith("/") else self.resolve(cid)
        data = self.block_get(cid)
        if cid.codec == 0x71:
            return dagcbor.decode(data)
        if cid.codec == 0x70:
            n = PBNode.decode(data)
            return {"Data": n.data, "Links": [{"Hash": l.cid, "Name": l.name, "Tsize": l.tsize}
                                              for l in n.links]}
        if cid.codec == 0x0200 or cid.codec == 0x0129:
            return json.loads(data)
        return data

    def fetch_dag(self, cid):
        """Ensure every block of the DAG under ``cid`` is stored locally."""
        n = 0
        with self.blockstore.session():
            for c in unixfs.walk_cids(self.fetcher, CID.decode(cid)):
                self.blockstore.protect(c)
                n += 1
                if n % 16 == 0:
                    self.blockstore.check_limit()
            self.blockstore.check_limit()
        return n

    # ---- pinning & GC ------------------------------------------------------
    def _pins_file(self):
        return os.path.join(self.repo, "pins.json") if self.repo else None

    def _load_pins(self):
        fn = self._pins_file()
        if fn and os.path.exists(fn):
            with open(fn) as f:
                return {CID.decode(c) for c in json.load(f)}
        return set()

    def _save_pins(self):
        fn = self._pins_file()
        if fn:
            tmp = fn + ".tmp"
            with open(tmp, "w") as f:
                json.dump(sorted(str(c) for c in self._pins), f)
            os.replace(tmp, fn)

    def pin_add(self, path, fetch=True) -> CID:
        """Pin a DAG (fetching any missing blocks first). Raises
        ``StorageFull`` and leaves it unpinned if it doesn't fit."""
        cid = self.resolve(path) if fetch else CID.decode(path)
        with self._pin_lock:
            new = cid not in self._pins
            self._pins.add(cid)  # pin first so GC keeps blocks as they arrive
        if fetch:
            try:
                self.fetch_dag(cid)
            except BaseException:
                if new:
                    with self._pin_lock:
                        self._pins.discard(cid)
                    self.blockstore.maybe_collect()  # release what was fetched
                raise
        with self._pin_lock:
            self._save_pins()
        if self.provider is not None:
            self.provider.notify()
        return cid

    def pin_rm(self, path):
        cid = CID.decode(path) if not str(path).startswith("/") else self.resolve(path)
        with self._pin_lock:
            self._pins.discard(cid)
            self._save_pins()
        self.blockstore.maybe_collect()

    def pin_ls(self):
        return sorted(self._pins, key=str)

    def _pinned_multihashes(self):
        """Every multihash reachable from a pin, walking only blocks we have."""
        keep = set()
        with self._pin_lock:
            stack = list(self._pins)
        inner = self.blockstore.inner
        while stack:
            c = stack.pop()
            if c.multihash in keep:
                continue
            keep.add(c.multihash)
            if c.codec not in (0x70, 0x71):
                continue
            try:
                data = inner.get(c, touch=False)
            except BlockNotFound:
                continue
            try:
                if c.codec == 0x70:
                    stack.extend(l.cid for l in PBNode.decode(data).links)
                else:
                    stack.extend(dagcbor.links(dagcbor.decode(data)))
            except ValueError:
                log.warning("cannot decode pinned block %s", c)
        return keep

    def gc(self, target_size=0) -> int:
        """Delete unpinned blocks, least recently used first, until stored
        data is at most ``target_size`` bytes (default 0: all unpinned
        blocks). Returns the number of blocks removed."""
        return self.blockstore.collect(target_size)[0]

    def repo_stat(self) -> dict:
        """Storage usage: ``size``, ``storage_max``, watermarks, block count
        and garbage-collection counters."""
        out = self.blockstore.usage()
        out["num_blocks"] = len(self.blockstore.keys())
        out.update(self.blockstore.stats)
        return out

    # ---- routing -----------------------------------------------------------
    def _require_dht(self):
        if self.dht is None:
            raise RuntimeError("DHT is disabled; create the node with dht=True")
        return self.dht

    def find_providers(self, cid, count=20, timeout=60.0):
        return self._require_dht().find_providers(cid, count, timeout)

    def find_peer(self, peer, timeout=60.0):
        return self._require_dht().find_peer(peer, timeout)

    def provide(self, cid):
        """Announce ``cid`` to the DHT now. Returns the number of peers that
        accepted the record. Kept announced afterwards if the strategy covers it."""
        dht = self._require_dht()
        if self.provider is not None:
            return self.provider.provide_now([cid])
        return dht.provide(cid)

    def provider_status(self) -> dict:
        """Reprovider state: strategy, keys, how many are due, counters."""
        return self.provider.status() if self.provider is not None else {"strategy": None}

    def _connect_providers(self, cid, max_peers=3):
        """Find providers of ``cid`` and connect to each as soon as it is found."""
        connected = []
        threads = []

        def connect(pid, addrs):
            try:
                self.host.connect_peer(pid, addrs)
                connected.append(pid)
            except Exception as e:
                log.debug("provider %s unreachable: %s", pid, e)

        def found(pid, addrs):
            if pid != self.peer_id and not self.host.connections(pid):
                t = threading.Thread(target=connect, args=(pid, addrs), daemon=True)
                t.start()
                threads.append(t)

        self.dht.find_providers(cid, count=max_peers, timeout=30, callback=found)
        for t in threads:
            t.join(timeout=30)
        return len(connected)

    # ---- IPNS --------------------------------------------------------------
    def _ipns_dir(self):
        return os.path.join(self.repo, "ipns") if self.repo else None

    def _load_ipns(self):
        d = self._ipns_dir()
        if not d or not os.path.isdir(d):
            return
        meta = {}
        try:
            with open(os.path.join(d, "published.json")) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            pass
        for fn in os.listdir(d):
            if not fn.endswith(".rec"):
                continue
            name = fn[:-4]
            try:
                with open(os.path.join(d, fn), "rb") as f:
                    rec = ipns.Record.decode(f.read())
            except (OSError, ipns.InvalidRecord) as e:
                log.warning("ignoring stored IPNS record %s: %s", fn, e)
                continue
            self._local_records[name] = rec
            self._ipns_seq[name] = rec.sequence
            self._ipns_published[name] = meta.get(name, {
                "published": 0, "lifetime": ipns.DEFAULT_LIFETIME.total_seconds()})

    def _save_ipns(self, name, rec):
        d = self._ipns_dir()
        if not d:
            return
        os.makedirs(d, exist_ok=True)
        tmp = os.path.join(d, name + ".rec.tmp")
        with open(tmp, "wb") as f:
            f.write(rec.encode())
        os.replace(tmp, os.path.join(d, name + ".rec"))
        tmp = os.path.join(d, "published.json.tmp")
        with open(tmp, "w") as f:
            json.dump(self._ipns_published, f)
        os.replace(tmp, os.path.join(d, "published.json"))

    def _network_sequence(self, name):
        """Highest valid sequence already in the DHT for ``name`` (or -1)."""
        best = -1
        for _, raw in self.dht.get_values(ipns.dht_key(name), quorum=3, timeout=20):
            try:
                r = ipns.Record.decode(raw)
                r.verify(name)
                best = max(best, r.sequence)
            except ipns.InvalidRecord:
                pass
        return best

    def name_publish(self, path, key=None, lifetime=ipns.DEFAULT_LIFETIME, sequence=None):
        """Sign an IPNS record pointing at ``path`` with ``key`` (default: the
        node identity) and publish it to the DHT if enabled. The record is kept
        in the repo and republished every ``ipns_republish_period`` (Kubo's
        4 h) with a fresh validity, so it never expires while the node runs.
        Returns ``(name, record)``."""
        key = key or self.identity
        if isinstance(path, CID):
            path = f"/ipfs/{path}"
        if not isinstance(lifetime, datetime.timedelta):
            lifetime = datetime.timedelta(seconds=lifetime)
        name = ipns.name_for_key(key.public_key)
        if sequence is None:
            if name not in self._ipns_seq and self.dht is not None and self.started:
                # first publish from this repo: continue the network's sequence
                self._ipns_seq[name] = self._network_sequence(name)
            sequence = self._ipns_seq.get(name, -1) + 1
        rec = ipns.Record.create(key, path, sequence, lifetime)
        self._ipns_seq[name] = sequence
        self._ipns_keys[name] = key
        self._local_records[name] = rec
        self._ipns_published[name] = {"published": time.time(),
                                      "lifetime": lifetime.total_seconds()}
        self.blockstore.put_block(rec.encode(), "ipns-record")
        self._save_ipns(name, rec)
        if self.dht is not None:
            self.dht.put_value(ipns.dht_key(name), rec.encode())
        return name, rec

    def name_resolve(self, name, recursive=True, depth=0) -> str:
        """Resolve an IPNS name or DNSLink domain to an ``/ipfs/...`` path."""
        if depth > 32:
            raise RuntimeError("IPNS recursion limit reached")
        name = name[6:] if name.startswith("/ipns/") else name
        name, _, sub = name.partition("/")
        if "." in name:
            from .dns import resolve_dnslink
            target = resolve_dnslink(name)
            if target is None:
                raise LookupError(f"no DNSLink record for {name}")
        else:
            target = self._resolve_ipns(name)
        if sub:
            target = target.rstrip("/") + "/" + sub
        if recursive and target.startswith("/ipns/"):
            return self.name_resolve(target, True, depth + 1)
        return target

    def _resolve_ipns(self, name) -> str:
        canonical = ipns.name_to_peer_id(name).to_cid().encode("base36")
        local = self._local_records
        records = []
        if canonical in local:
            records.append(local[canonical])
        if self.dht is not None:
            for _, raw in self.dht.get_values(ipns.dht_key(name), quorum=4, timeout=30):
                try:
                    r = ipns.Record.decode(raw)
                    r.verify(name)
                    records.append(r)
                except ipns.InvalidRecord as e:
                    log.debug("bad IPNS record: %s", e)
        for gw in self.gateways:
            try:
                r = ipns.Record.decode(gw.get_ipns_record(name))
                r.verify(name)
                records.append(r)
            except Exception as e:
                log.debug("gateway IPNS lookup failed: %s", e)
        best = ipns.select_best(records)
        if best is None:
            raise LookupError(f"could not resolve IPNS name {name}")
        return best.path
