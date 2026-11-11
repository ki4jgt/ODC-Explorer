"""Self-contained tests (no external IPFS node or internet required).

Run: python3 -m unittest discover -s tests -v
"""

import datetime
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import (CID, Ed25519PrivateKey, Host, IPFSNode, Importer, MemoryBlockstore,
                    Multiaddr, PeerID, dagcbor, ipns, multibase, multihash, unixfs, varint)
from basilisk_ipfs.blockstore import FilesystemBlockstore
from basilisk_ipfs.crypto import chacha20poly1305 as aead, ed25519, x25519


class TestMultiformats(unittest.TestCase):
    def test_varint(self):
        for n in [0, 1, 127, 128, 300, 2 ** 32, 2 ** 63 - 1]:
            self.assertEqual(varint.decode(varint.encode(n)), (n, len(varint.encode(n))))
        self.assertEqual(varint.encode(300), b"\xac\x02")

    def test_multibase_roundtrip(self):
        data = b"\x00\x00hello multibase"
        for base in multibase.names():
            self.assertEqual(multibase.decode(multibase.encode(data, base)), data, base)
        self.assertEqual(multibase.encode(b"yes mani !", "base58btc"), "z7paNL19xttacUY")

    def test_cid(self):
        v0 = CID.decode("QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH")
        self.assertEqual(v0.version, 0)
        self.assertEqual(str(v0.to_v1()), "bafybeif7ztnhq65lumvvtr4ekcwd2ifwgm3awq4zfr3srh462rwyinlb4y")
        self.assertEqual(CID.decode(str(v0.to_v1())).to_v0(), v0)
        self.assertEqual(CID.from_bytes(v0.to_v1().to_bytes()), v0.to_v1())
        raw = CID.from_data(b"", "raw")
        self.assertEqual(str(raw), "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
        self.assertEqual(CID.from_prefix(raw.prefix(), b""), raw)
        self.assertEqual(CID.decode(raw.encode("base58btc")), raw)

    def test_multihash(self):
        mh = multihash.digest(b"foo", "sha2-256")
        self.assertTrue(multihash.verify(mh, b"foo"))
        self.assertFalse(multihash.verify(mh, b"bar"))
        self.assertEqual(multihash.decode(multihash.digest(b"x", "blake2b-256"))[0], 0xB220)

    def test_multiaddr(self):
        s = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWJgwhiomKUyAcqdDSq2PaMA6uM8QTAuDAuSofYfy4X6Qe"
        ma = Multiaddr(s)
        self.assertEqual(str(Multiaddr(ma.to_bytes())), s)
        self.assertEqual(ma.tcp_target(), ("127.0.0.1", 4001))
        self.assertEqual(str(ma.peer_id), s.rsplit("/", 1)[1])
        q = Multiaddr("/ip6/::1/udp/4001/quic-v1/webtransport")
        self.assertEqual(Multiaddr(q.to_bytes()), q)
        self.assertIsNone(q.tcp_target())


class TestCrypto(unittest.TestCase):
    def test_ed25519_rfc8032(self):
        sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk = ed25519.public_key(sk)
        self.assertEqual(pk.hex(), "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig = ed25519.sign(sk, b"\x72")
        self.assertEqual(sig.hex(), "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        self.assertTrue(ed25519.verify(pk, b"\x72", sig))
        self.assertFalse(ed25519.verify(pk, b"\x73", sig))

    def test_x25519(self):
        a, b = x25519.generate_private(), x25519.generate_private()
        self.assertEqual(x25519.shared(a, x25519.public_key(b)), x25519.shared(b, x25519.public_key(a)))

    def test_aead(self):
        key, nonce = os.urandom(32), os.urandom(12)
        for n in (0, 1, 63, 64, 65, 1000, 70000):
            pt = os.urandom(n)
            ct = aead.encrypt(key, nonce, pt, b"ad")
            self.assertEqual(aead.decrypt(key, nonce, ct, b"ad"), pt)
        bad = bytearray(aead.encrypt(key, nonce, b"hello"))
        bad[0] ^= 1
        with self.assertRaises(aead.InvalidTag):
            aead.decrypt(key, nonce, bytes(bad))

    def test_peer_id(self):
        k = Ed25519PrivateKey(b"\x01" * 32)
        pid = k.peer_id()
        self.assertTrue(str(pid).startswith("12D3KooW"))
        self.assertEqual(PeerID.decode(str(pid)), pid)
        self.assertEqual(PeerID.decode(str(pid.to_cid())), pid)
        self.assertEqual(pid.extract_public_key(), k.public_key)


class TestCodecs(unittest.TestCase):
    def test_dagcbor(self):
        cid = CID.from_data(b"x")
        obj = {"b": [1, -2, 3.5, None, True], "a": b"\x00\x01", "link": cid, "s": "héllo", "big": 2 ** 40}
        enc = dagcbor.encode(obj)
        self.assertEqual(dagcbor.decode(enc), obj)
        self.assertEqual(dagcbor.encode(dagcbor.decode(enc)), enc)  # deterministic
        self.assertEqual(dagcbor.links(obj), [cid])


class TestUnixFS(unittest.TestCase):
    KNOWN = [  # (data, kwargs, CID produced by `ipfs add`)
        (b"", {}, "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"),
        (b"hello world\n", {}, "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o"),
        (b"", {"cid_version": 1}, "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"),
    ]

    def test_known_cids(self):
        for data, kw, expected in self.KNOWN:
            self.assertEqual(str(Importer(MemoryBlockstore(), **kw).add_bytes(data).cid), expected)

    def test_roundtrip_and_ranges(self):
        data = os.urandom(3 * 262144 + 12345)
        for kw in ({}, {"cid_version": 1}, {"chunk_size": 1000, "max_links": 3}):
            bs = MemoryBlockstore()
            cid = Importer(bs, **kw).add_bytes(data).cid
            self.assertEqual(unixfs.read(bs, cid), data)
            self.assertEqual(unixfs.read(bs, cid, 5000, 300000), data[5000:305000])
            self.assertEqual(unixfs.read(bs, cid, len(data) - 10), data[-10:])
            self.assertEqual(unixfs.stat(bs, cid)["size"], len(data))

    def test_directory_and_hamt(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(f"{tmp}/d/sub")
            with open(f"{tmp}/d/sub/x.txt", "w") as f:
                f.write("x")
            for i in range(50):
                with open(f"{tmp}/d/f{i}", "w") as f:
                    f.write(str(i))
            os.symlink("sub/x.txt", f"{tmp}/d/link")
            for threshold in (unixfs.HAMT_THRESHOLD, 100):  # 100 forces sharding
                bs = MemoryBlockstore()
                root = Importer(bs, hamt_threshold=threshold).add_path(f"{tmp}/d").cid
                names = {e.name for e in unixfs.ls(bs, root)}
                self.assertEqual(names, {f"f{i}" for i in range(50)} | {"sub", "link"})
                self.assertEqual(unixfs.read(bs, unixfs.resolve(bs, f"/ipfs/{root}/f42")), b"42")
                self.assertEqual(unixfs.read(bs, unixfs.resolve(bs, f"{root}/sub/x.txt")), b"x")
                out = f"{tmp}/out{threshold}"
                unixfs.export(bs, root, out)
                self.assertEqual(os.readlink(f"{out}/link"), "sub/x.txt")
                with open(f"{out}/f7") as f:
                    self.assertEqual(f.read(), "7")
        finally:
            shutil.rmtree(tmp)

    def test_murmur3(self):
        # reference values from the canonical MurmurHash3_x64_128 implementation
        self.assertEqual(unixfs.murmur3_x64_128(b""), (0, 0))
        self.assertEqual(unixfs.murmur3_x64_128(b"hello")[0], 0xCBD8A7B341BD9B02)


class TestBlockstores(unittest.TestCase):
    def test_fs_blockstore(self):
        tmp = tempfile.mkdtemp()
        try:
            bs = FilesystemBlockstore(tmp)
            cid = bs.put_block(b"data")
            self.assertTrue(bs.has(cid.to_v1()))
            self.assertEqual(bs.get(cid), b"data")
            self.assertEqual(list(bs.keys()), [cid.multihash])
            with self.assertRaises(ValueError):
                bs.put(cid, b"wrong")
        finally:
            shutil.rmtree(tmp)


class TestIPNS(unittest.TestCase):
    def test_record(self):
        key = Ed25519PrivateKey()
        rec = ipns.Record.create(key, CID.from_data(b"hi"), sequence=3)
        name = ipns.name_for_key(key.public_key)
        dec = ipns.Record.decode(rec.encode())
        self.assertTrue(dec.verify(name))
        self.assertEqual(dec.sequence, 3)
        other = ipns.name_for_key(Ed25519PrivateKey().public_key)
        with self.assertRaises(ipns.InvalidRecord):
            dec.verify(other)
        expired = ipns.Record.create(key, "/ipfs/x", lifetime=datetime.timedelta(seconds=-1))
        with self.assertRaises(ipns.InvalidRecord):
            ipns.Record.decode(expired.encode()).verify(name)


class TestNetworkLocal(unittest.TestCase):
    """Two in-process nodes talking libp2p over loopback TCP."""

    def test_host_ping_identify(self):
        with Host() as a, Host() as b:
            addr = a.listen("/ip4/127.0.0.1/tcp/0")
            b.connect(f"{addr}/p2p/{a.peer_id}")
            self.assertEqual(len(b.ping(a.peer_id, 2)), 2)
            info = b.identify(a.peer_id)
            self.assertIn("/ipfs/ping/1.0.0", info.protocols)

    def test_bitswap_between_nodes(self):
        data = os.urandom(1_000_000)
        with IPFSNode(listen=["/ip4/127.0.0.1/tcp/0"]) as a, IPFSNode(listen=[]) as b:
            root = a.add_bytes(data)
            b.connect(a.id()["Addresses"][0])
            self.assertEqual(b.cat(root), data)
            self.assertTrue(b.block_has(root))

    def test_repo_persistence_pins_gc(self):
        tmp = tempfile.mkdtemp()
        try:
            with IPFSNode(tmp, offline=True) as n:
                pid = n.peer_id
                keep = n.add_bytes(b"keep me")
                drop = n.add_bytes(b"drop me", pin=False)
                self.assertEqual(n.gc(), 1)
                self.assertFalse(n.block_has(drop))
            with IPFSNode(tmp, offline=True) as n:
                self.assertEqual(n.peer_id, pid)
                self.assertEqual(n.cat(keep), b"keep me")
                self.assertIn(keep, n.pin_ls())
        finally:
            shutil.rmtree(tmp)

    def test_dag_cbor_paths(self):
        with IPFSNode(offline=True) as n:
            leaf = n.add_bytes(b"leaf")
            root = n.dag_put({"name": "x", "file": leaf})
            obj = n.dag_get(root)
            self.assertEqual(obj["file"], leaf)
            self.assertEqual(n.fetch_dag(root), 2)


if __name__ == "__main__":
    unittest.main()
