"""Long-lived state: the basilisk-ipfs node and the current catalog root.

The explorer is a full IPFS peer: it listens for inbound connections on a port
basilisk-ipfs chooses, maps it on the router and verifies reachability, and serves
every cached block over Bitswap. Announcing those blocks on the DHT, and
re-announcing them, is left entirely to basilisk-ipfs' provider (strategy "all"),
so other readers can find this node. Content comes only from the IPFS network;
there is no HTTP gateway fallback.
"""

import logging
import os
import threading
import time

from .chain import BlockCache, Catalog

log = logging.getLogger("odc_explorer")

# The ODC root is published under this IPNS name (spec Section 7).
ODC_IPNS_NAME = "k51qzi5uqu5dlw1jsigau9m0tfqupv2zhyr2bwkfvycsq38oqqzr35mk6eq3mg"

ROOT_TTL = 60           # seconds between IPNS re-resolutions
IPNS_QUORUM = 16        # IPNS records to collect per lookup (Kubo's default)
BLOCK_CACHE_BYTES = 64 * 1024 * 1024   # in-memory cache of parsed blocks


class Explorer:
    def __init__(self, repo, node=None, ipns_name=ODC_IPNS_NAME):
        self.ipns_name = ipns_name
        self.started_at = time.time()
        self._next_resolve = 0.0
        self.repo = os.path.abspath(os.path.expanduser(repo))
        os.makedirs(self.repo, exist_ok=True)
        if node is None:
            from basilisk_ipfs import IPFSNode
            # The repo keeps basilisk-ipfs' block cache, identity and provider state
            # across restarts. No listen address is given, so basilisk-ipfs picks its
            # own port. NAT port mapping, AutoNAT, AutoRelay and hole punching
            # stay on (the basilisk-ipfs defaults) so other readers can reach this node.
            # basilisk-ipfs announces every cached block ("all") and re-announces them.
            node = IPFSNode(os.path.join(self.repo, "ipfs"), dht=True,
                            gateways=(), fetch_timeout=45, storage_max="2GB",
                            provide_strategy="all").start()
        self.node = node
        self._root_file = os.path.join(self.repo, "last_root")
        self.root, self.root_seq = self._load_root()
        self.resolved_at = 0.0
        self.resolve_error = None
        self._ready = threading.Event()
        # Parsed blocks, keyed by CID and shared by every root, so blocks that
        # don't change between publications stay cached. basilisk-ipfs still owns the
        # blocks on disk.
        self.block_cache = BlockCache(BLOCK_CACHE_BYTES)
        if self.root:
            self._ready.set()
        threading.Thread(target=self._refresh_loop, daemon=True, name="odc-ipns").start()

    # ---- root ----------------------------------------------------------------
    def _load_root(self):
        """Last root and its IPNS sequence number (None if unknown)."""
        try:
            with open(self._root_file, encoding="utf-8") as f:
                lines = f.read().split()
        except OSError:
            return None, None
        cid = lines[0] if lines else None
        seq = int(lines[1]) if len(lines) > 1 and lines[1].isdigit() else None
        return cid, seq

    def _save_root(self):
        with open(self._root_file, "w", encoding="utf-8") as f:
            f.write(self.root + ("" if self.root_seq is None else f"\n{self.root_seq}") + "\n")

    def _latest_record(self):
        """(sequence, /ipfs/ path) of the newest valid IPNS record found.

        Right after ODC publishes, some DHT nodes still hold older records, so
        collect several (as Kubo does) and keep the one with the highest
        sequence. Uses basilisk-ipfs' DHT and IPNS record handling directly, because
        name_resolve() doesn't say which sequence it chose.
        """
        dht = getattr(self.node, "dht", None)
        if dht is None:                        # no DHT (tests, offline): plain resolve
            return None, self.node.name_resolve(self.ipns_name)
        from basilisk_ipfs import ipns
        records = []
        for _, raw in dht.get_values(ipns.dht_key(self.ipns_name), quorum=IPNS_QUORUM, timeout=30):
            try:
                rec = ipns.Record.decode(raw)
                rec.verify(self.ipns_name)     # signature, name binding, expiry
                records.append(rec)
            except Exception as e:
                log.debug("ignoring IPNS record: %s", e)
        best = ipns.select_best(records)
        if best is None:
            raise LookupError(f"no valid IPNS record found for {self.ipns_name}")
        return best.sequence, best.path

    def _fetch(self, cid):
        # node.cat handles both raw blocks and UnixFS files; cap the read just
        # past the spec limit so oversize blocks are rejected without a full pull.
        provider = getattr(self.node, "provider", None)
        new = provider is not None and not self.node.block_has(cid)
        data = self.node.cat(f"/ipfs/{cid}", 0, 256 * 1024 + 1)
        # A block that just came from the network: let basilisk-ipfs' provider
        # announce it soon rather than at its next periodic scan.
        if new:
            provider.notify()
        return data

    def resolve_now(self):
        try:
            seq, path = self._latest_record()
            cid = path.split("/")[2]
            self.resolve_error = None
            self.resolved_at = time.time()
            if seq is not None and self.root_seq is not None and seq < self.root_seq:
                # A stale DHT node answered: never go back to an older catalog.
                log.info("ignoring older IPNS record (sequence %d < %d)", seq, self.root_seq)
            elif cid != self.root or (seq is not None and seq != self.root_seq):
                if cid != self.root:
                    log.info("ODC root is now %s (sequence %s)", cid, seq)
                self.root, self.root_seq = cid, seq
                self._save_root()
            self._ready.set()
        except Exception as e:
            log.warning("IPNS resolution failed: %s", e)
            self.resolve_error = str(e)

    def _refresh_loop(self):
        while True:
            self.resolve_now()
            wait = ROOT_TTL if self.resolve_error is None else 20
            self._next_resolve = time.time() + wait
            time.sleep(wait)

    def next_resolve_in(self):
        return max(0.0, self._next_resolve - time.time()) if self._next_resolve else None

    def close(self):
        """Stop the IPFS node: closes connections and removes router port mappings."""
        try:
            self.node.stop()
        except Exception as e:
            log.debug("node stop failed: %s", e)

    def wait_ready(self, timeout=90):
        return self._ready.wait(timeout)

    def catalog(self):
        """The catalog at the latest resolved root, reading through the shared
        block cache; basilisk-ipfs' blockstore and garbage collector manage the disk."""
        root = self.root
        if root is None:
            raise LookupError("the ODC root has not been resolved yet")
        return Catalog(self._fetch, root, self.block_cache)
