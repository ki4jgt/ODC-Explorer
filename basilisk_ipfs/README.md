# basilisk-ipfs

A pure-Python implementation of IPFS, built only on the standard library and
meant to be imported into other programs. It is a real network peer: it speaks
libp2p (QUIC, and TCP + Noise + Yamux), Bitswap, the Kademlia DHT and IPNS, so it
interoperates directly with Kubo and the public IPFS network. It does not wrap
a daemon.

Requires Python 3.9+. No third-party dependencies.

**Crypto backend.** ChaCha20-Poly1305, X25519 and Ed25519 run through
OpenSSL's `libcrypto`, the library Python's own `ssl` module uses, loaded with
`ctypes`. If `libcrypto` can't be found, is older than 1.1.1, or fails a
startup self-test against the RFC test vectors, basilisk-ipfs uses its pure-Python
implementations instead, which are correct but much slower. Check
`basilisk_ipfs.crypto.BACKEND` to see which is active, and set
`BASILISK_IPFS_PURE_PYTHON=1` to force pure Python.

| Backend | Connect (local) | Transfer |
|---|---|---|
| OpenSSL via ctypes | ~12 ms | ~30 MB/s |
| Pure Python | ~70 ms | ~2.4 MB/s |

**QUIC.** basilisk-ipfs dials `/udp/<port>/quic-v1` addresses using the QUIC client
in OpenSSL 3.2+ (`libssl`, through `ctypes`). It uses libp2p's TLS rules: a
self-signed certificate carrying a signed copy of the identity key, the ALPN
value `libp2p`, and certificates from both sides. Where both are available,
QUIC is tried before TCP, as Kubo does; it connects in about half the time.

Where OpenSSL is missing or older than 3.2, QUIC addresses count as
undialable and everything runs over TCP + Noise + Yamux as before.
`basilisk_ipfs.p2p.quic.AVAILABLE` says which applies, and `BASILISK_IPFS_NO_QUIC=1` turns
QUIC off. OpenSSL before 3.5 has no QUIC server, so basilisk-ipfs dials QUIC but
only accepts connections over TCP.

## Quick start

```python
from basilisk_ipfs import IPFSNode

# Join the public network (DHT routing + Bitswap)
with IPFSNode(dht=True) as node:
    print(node.cat("/ipfs/QmdmQXB2mzChmMeKY47C43LxUdg1NDJ5MWcKMKxDu7RgQm/1 - Barrel - Part 1/1 - Barrel - Part 1 - alt.txt"))

    cid = node.add_bytes(b"hello world\n")       # same CID as `ipfs add`
    root = node.add_path("./site", wrap=True)     # directories, symlinks, HAMT sharding
    for entry in node.ls(root.cid):
        print(entry.name, entry.cid, entry.size)
    node.get(root.cid, "/tmp/site-copy")

    name, record = node.name_publish(cid)         # IPNS (signed, put to the DHT)
    print(node.name_resolve(name))
```

Connect to a specific peer (for example a local Kubo daemon) instead of the DHT:

```python
node = IPFSNode(peers=["/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW..."]).start()
data = node.cat("QmSomeCid")
node.stop()
```

Persistent repository (blocks, identity key, pins):

```python
node = IPFSNode("~/.basilisk-ipfs")     # identity survives restarts
node.pin_add("/ipfs/bafy...")    # fetch the whole DAG and pin it
node.gc()                        # delete unpinned blocks
```

Storage limit with automatic garbage collection:

```python
node = IPFSNode("~/.basilisk-ipfs", storage_max="10GB")   # or bytes; "512MiB" etc.
# gc_high_water=0.9, gc_low_water=0.8 are the defaults

node.repo_stat()   # {'size': ..., 'storage_max': ..., 'num_blocks': ..., 'blocks_evicted': ...}
```

- When usage goes over 90% of the limit, the node deletes the least recently
  used unpinned blocks in the background until usage is under 80%. Storing or
  reading a block counts as using it, and the order survives restarts.
- Pinned blocks are never deleted. Neither are blocks belonging to an import
  or `pin_add` that is still running.
- `add_*`, `block_put`, `dag_put` and `pin_add` raise `StorageFull` if the
  data can't fit even after deleting every unpinned block. A refused add or pin
  is not pinned, and its blocks get cleaned up.
- Blocks fetched by `cat`, `get` or `ls` act as a cache. They trigger
  collection but are never refused, so you can stream a file larger than the
  limit.
- `node.gc()` still deletes every unpinned block, and `node.gc(target_size=n)`
  deletes the oldest ones until usage is at most `n` bytes.

## Public addresses and NAT

The node finds and announces its public address following the libp2p specs:

1. **Identify `observedAddr`.** Outbound connections leave from the listen
   port, so peers report the address the NAT maps it to. An observation
   counts only if it came over a connection that used our listen port. The
   address is activated once 4 distinct observers agree (go-libp2p's
   threshold; IPv4 observers grouped by address, IPv6 by /56).
2. **Port mapping.** UPnP IGD or NAT-PMP (RFC 6886) maps the listen port on
   the router, as Kubo does. Turn this off with `nat_port_map=False`.
3. **AutoNAT v2.** Other peers dial each candidate address back and prove it
   with a nonce. An address counts as reachable or unreachable once 3
   servers agree, and it's rechecked every 15 minutes. Addresses that turn
   out to be unreachable are not announced.
4. **Identify push.** Connected peers are told whenever the announced
   addresses (or supported protocols) change.
5. **Circuit Relay v2 (AutoRelay).** When AutoNAT finds the node isn't
   directly reachable, it reserves slots on 2 public relays, announces
   `<relay>/p2p/<relay-id>/p2p-circuit` addresses, renews the reservations,
   and keeps those connections alive. Peers then reach it through a relay,
   as with Kubo behind a NAT. It can also dial NATed peers through their
   relay addresses.
6. **DCUtR hole punching.** A relayed connection is limited: it only carries
   Identify, Ping and DCUtR. The two peers swap their observed addresses and
   time a TCP simultaneous open from their listen ports, which gives them a
   direct connection. Bitswap and other protocols then use that connection.

Kubo's equivalent settings are `Swarm.RelayClient`, `Swarm.RelayService` and
`Swarm.EnableHolePunching`. Here they are `relay_client=True` (or `"always"`),
`static_relays=[...]`, `relay_service=False` and `hole_punching=True`.

```python
node = IPFSNode(dht=True, listen=["/ip4/0.0.0.0/tcp/4002"])
node.host.reachability     # 'public', 'private' or 'unknown'
node.host.public_addrs()   # what we currently announce publicly
```

If your router supports neither UPnP nor NAT-PMP, forward a fixed listen
port (as above) by hand, and AutoNAT will confirm and announce it. You can
also set addresses yourself, the same way as Kubo's `Addresses.*` settings:

```python
IPFSNode(announce=["/ip4/203.0.113.9/tcp/4002"])           # exactly these
IPFSNode(append_announce=["/dns4/node.example.com/tcp/4002"])  # in addition
IPFSNode(no_announce=["10.0.0.0/8", "/ip4/192.168.0.0/ipcidr/16"])
```

To help other nodes check their own reachability, pass
`autonat_service=True`. That turns on a rate-limited AutoNAT v2 server, which
requires dial data before dialing any IP other than the requester's observed
one, and never reuses its listen port for dial-backs.

## Connections and open files

A node on the public network quickly connects to more than a hundred peers,
mostly through DHT lookups. Like Kubo, basilisk-ipfs keeps that bounded:

- **Connection manager** (Kubo's `Swarm.ConnMgr`). Once there are more than
  `conn_high_water` (96) connections, the least valuable ones are closed until
  `conn_low_water` (32) remain.
  - **Never closed:** connections younger than `conn_grace_period` (20 s),
    relays holding our reservation, and peers passed in `peers=[...]`.
  - **Closed last:** peers that recently delivered blocks, then DHT
    routing-table peers.
  - **Among the rest:** the least recently used go first.
  - **Turning it off:** set `conn_high_water=None`.
- **Open-file limit.** At start-up the soft `RLIMIT_NOFILE` is raised to
  `fd_limit` (8192, Kubo's `IPFS_FD_MAX`) if the hard limit allows; it's never
  lowered. Set `fd_limit=None` to leave it alone.
- **Dial guard.** When 90% of descriptors are in use, new dials fail with a
  clear `DialError` instead of "Too many open files", and the connection
  manager is asked to free some.
- **Descriptor cost.** Each QUIC connection uses one descriptor: a single
  shared reactor thread drives every QUIC connection through `epoll`. A TCP
  connection also uses one.

```python
node = IPFSNode(dht=True, conn_low_water=16, conn_high_water=48)
node.connmgr.protect(peer_id, "my-app")    # keep this peer connected
node.connmgr.tag_peer(peer_id, "my-app", 5)  # or just make it less likely to be closed
```

## Staying findable (reproviding and IPNS republishing)

With `dht=True`, the node announces its content to the DHT and keeps doing
so, like Kubo:

- **What gets announced:** `provide_strategy` controls this, like Kubo's
  `Provide.Strategy`. Options are `"all"` (every block, the default),
  `"pinned"`, `"roots"`, or `None` to announce nothing.
- **Re-announcing:** every key is announced again every 22 hours
  (`reprovide_interval`), before DHT servers drop records after 48 hours.
  Keys are worked through in DHT keyspace order by 8 workers, and failed
  announcements are retried with increasing delays.
- **Restarts:** the time each key was last announced is stored in
  `provider.sqlite` in the repo, so restarting doesn't re-announce everything.
- **Address wait:** announcing waits until the node has addresses others can
  use: a public address confirmed by AutoNAT, or relay addresses if it's
  behind a NAT. Records carry those addresses. After 3 minutes it announces
  anyway.
- **IPNS:** records are stored in the repo and republished every 4 hours
  (`ipns_republish_period`) with a fresh 48-hour validity and the next
  sequence number. Before a name's first publish from a repo, the node checks
  the DHT for the current sequence number.

```python
node = IPFSNode("~/.basilisk-ipfs", dht=True, provide_strategy="pinned")
node.add_path("./site")          # announced as soon as addresses are usable
node.add_bytes(b"x", provide=True)   # also announce this root immediately
node.provider_status()           # {'keys': ..., 'due': ..., 'provided': ..., ...}
```

When fetching, Bitswap asks connected peers first. If nothing has arrived
after 1 second (Kubo's provider search delay), it starts a DHT provider
search in parallel and connects to each provider as soon as it's found.

## `IPFSNode` API

| Area | Methods |
|---|---|
| Lifecycle | `start()`, `stop()`, context manager |
| Content | `add_bytes`, `add_stream`, `add_path(wrap=)`, `cat`, `cat_stream(offset, length)`, `ls`, `stat`, `get`, `resolve` |
| Blocks/DAG | `block_get`, `block_put`, `block_has`, `block_rm`, `dag_put`, `dag_get`, `fetch_dag` |
| Pinning | `pin_add`, `pin_rm`, `pin_ls`, `gc` |
| Peers | `connect`, `disconnect`, `peers`, `ping`, `id` |
| Routing | `find_providers`, `find_peer`, `provide` (needs `dht=True`) |
| Naming | `name_publish`, `name_resolve` (IPNS and DNSLink) |

Import options mirror `ipfs add`: `cid_version`, `raw_leaves`, `chunk_size`,
`hash_fn`, `max_links`. Content is fetched from the local store first, then
from connected peers over Bitswap, then from DHT providers, and finally from
any `gateways=[...]` given (trustless gateways; every block is hash-verified).

## Layers

Every layer can be used on its own:

| Module | What it is |
|---|---|
| `varint`, `multibase`, `multihash`, `multicodec`, `cid`, `multiaddr` | Multiformats |
| `dagpb`, `dagcbor`, `unixfs` | IPLD codecs and the UnixFS importer/exporter (balanced DAG, HAMT directories) |
| `blockstore` | `MemoryBlockstore`, `FilesystemBlockstore` (flatfs-style layout) |
| `crypto.*` | Ed25519, X25519, ChaCha20-Poly1305, plus RSA/secp256k1/P-256 verification |
| `keys` | libp2p keys and peer IDs |
| `p2p.multistream`, `p2p.noise`, `p2p.yamux`, `p2p.host` | libp2p: protocol negotiation, secure channel, muxer, host with Identify and Ping |
| `bitswap` | Bitswap 1.2.0/1.1.0/1.0.0, both client and server |
| `dht` | Kademlia client: `FIND_NODE`, `GET_PROVIDERS`, `ADD_PROVIDER`, `GET_VALUE`, `PUT_VALUE` |
| `ipns`, `dns` | IPNS V1+V2 records; DNS TXT for `/dnsaddr` and DNSLink |
| `http_client` | `KuboClient` (Kubo RPC API) and `GatewayClient` (trustless gateway) |

Low-level example:

```python
from basilisk_ipfs import Host, Bitswap, MemoryBlockstore, CID

host = Host()
host.listen("/ip4/0.0.0.0/tcp/4002")
bs = Bitswap(host, MemoryBlockstore())
host.connect("/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...")
block = bs.get(CID.decode("bafkrei..."))

def echo(stream):                      # custom libp2p protocols
    stream.write(stream.read_all()); stream.close()
host.set_stream_handler("/my/echo/1.0.0", echo)
```

## Command line

```
python -m basilisk_ipfs add ./file            # offline: print the CID
python -m basilisk_ipfs cat /ipfs/<cid>       # fetch over the public network
python -m basilisk_ipfs --peer /ip4/127.0.0.1/tcp/4001/p2p/<id> --no-dht get <cid> -o out
python -m basilisk_ipfs serve --repo ./repo   # run a node that serves its blocks
```

## Tests

```
python3 -m unittest discover -s tests -v
```

`tests/test_offline.py` needs no network. `tests/test_kubo_interop.py` runs
against a local Kubo node (set `IPFS_API` / `IPFS_SWARM_HOST` / `IPFS_SWARM_PORT`)
and skips itself when none is reachable.

## Verified interoperability (Kubo 0.43.1)

- File and directory CIDs match `ipfs add` / `ipfs add -r` byte for byte. This
  covers CIDv0 and v1, raw leaves, custom chunk sizes, multi-level trees,
  symlinks, hidden-file exclusion and HAMT-sharded directories.
- Bitswap works in both directions: we fetch from Kubo, and Kubo fetches from us.
- The public DHT works: bootstrap via `/dnsaddr`, provider and peer lookups, and
  reading content from the network.
- IPNS works in both directions: Kubo resolves records we publish, and we
  resolve and verify Kubo's records.

## Limitations

- Transports: QUIC (outbound only, with OpenSSL ≥ 3.2), TCP, and circuit
  relays reached over either. The node doesn't listen for QUIC, so it
  announces only TCP and relay addresses. WebTransport, WebRTC and WebSockets
  are not implemented, so browser peers can't be dialed.
- Throughput is about 30 MB/s per connection with the OpenSSL backend; the
  Python stream framing and multiplexing code is now the limit. Without
  OpenSSL it's about 2–5 MB/s. On macOS, OpenSSL is only found if it was
  installed with Homebrew, because basilisk-ipfs never loads the system's
  unversioned `libcrypto` (doing so crashes the process).
- The DHT runs in client mode only and does not answer other peers' queries.
  `provide()` only helps if your listen address is publicly reachable.
- Hole punching is TCP-only, because QUIC punching needs a QUIC listener (Kubo
  punches over both). So it fails
  behind NATs that change the port for each destination (symmetric NAT). The
  peer then stays reachable through the relay, but only for the limited
  protocols listed above.
- There is a connection manager (see "Connections and open files") but not
  go-libp2p's full resource manager, which limits memory and streams per
  peer and per protocol.
- New keys are always Ed25519. RSA, secp256k1 and ECDSA peer keys are supported
  for verification only.
- MFS (`ipfs files`), pubsub, CAR import/export and trickle DAGs are not implemented.
