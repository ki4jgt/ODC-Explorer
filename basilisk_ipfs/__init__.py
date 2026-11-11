"""basilisk-ipfs — a pure-Python (standard library only) implementation of IPFS.

Quick start::

    from basilisk_ipfs import IPFSNode

    with IPFSNode(peers=["/ip4/127.0.0.1/tcp/4001/p2p/12D3Koo..."]) as node:
        cid = node.add_bytes(b"hello world")
        print(node.cat("/ipfs/bafy..."))

Layers (each usable on its own):

* multiformats: :mod:`varint`, :mod:`multibase`, :mod:`multihash`,
  :mod:`multicodec`, :class:`CID`, :class:`Multiaddr`
* IPLD codecs: :mod:`dagpb`, :mod:`dagcbor`; :mod:`unixfs` (import/export)
* storage: :class:`MemoryBlockstore`, :class:`FilesystemBlockstore`,
  :class:`ManagedBlockstore` (size limit + LRU garbage collection)
* libp2p: :class:`Host` (TCP + Noise + Yamux + multistream, Identify, Ping)
* exchange & routing: :class:`Bitswap`, :class:`DHT`, :mod:`ipns`, :mod:`dns`
* HTTP: :class:`KuboClient` (RPC API), :class:`GatewayClient` (trustless gateway)
"""

from . import dagcbor, dagpb, ipns, multibase, multicodec, multihash, unixfs, varint
from .bitswap import Bitswap, BlockUnavailable
from .blockstore import BlockNotFound, FilesystemBlockstore, MemoryBlockstore, StorageFull
from .cid import CID
from .dht import DHT
from .http_client import GatewayClient, KuboClient
from .keys import Ed25519PrivateKey, PeerID, PublicKey
from .multiaddr import Multiaddr
from .node import IPFSNode
from .p2p.host import Host
from .storage import ManagedBlockstore
from .unixfs import Importer

__version__ = "0.1.0"

__all__ = [
    "IPFSNode", "CID", "Multiaddr", "PeerID", "PublicKey", "Ed25519PrivateKey",
    "Host", "Bitswap", "DHT", "Importer", "MemoryBlockstore", "FilesystemBlockstore",
    "KuboClient", "GatewayClient", "BlockNotFound", "BlockUnavailable",
    "StorageFull", "ManagedBlockstore",
    "dagcbor", "dagpb", "ipns", "multibase", "multicodec", "multihash", "unixfs", "varint",
]
