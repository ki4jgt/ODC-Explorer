"""Interoperability tests against a running Kubo node.

Skipped automatically when no node is reachable. Configure with
IPFS_API (default http://127.0.0.1:5001) and IPFS_SWARM_HOST/PORT
(default 127.0.0.1:4001).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import GatewayClient, Importer, IPFSNode, KuboClient, MemoryBlockstore, ipns

API = os.environ.get("IPFS_API", "http://127.0.0.1:5001")
SWARM = (os.environ.get("IPFS_SWARM_HOST", "127.0.0.1"), os.environ.get("IPFS_SWARM_PORT", "4001"))

try:
    _KUBO = KuboClient(API, timeout=60)
    _KUBO_ID = _KUBO.id()["ID"]
except Exception:
    _KUBO = None


@unittest.skipIf(_KUBO is None, "no Kubo node reachable")
class TestKuboInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.addr = f"/ip4/{SWARM[0]}/tcp/{SWARM[1]}/p2p/{_KUBO_ID}"

    def test_cids_match_ipfs_add(self):
        for size in (0, 10, 262144, 262145, 1_500_000):
            data = os.urandom(size)
            for kw, opts in (({}, {}), ({"cid_version": 1}, {"cid_version": 1}),
                             ({"raw_leaves": True}, {"raw_leaves": True})):
                mine = Importer(MemoryBlockstore(), **kw).add_bytes(data).cid
                theirs = _KUBO.add_bytes(data, only_hash=True, **opts)
                self.assertEqual(str(mine), theirs, (size, kw))

    def test_fetch_from_kubo(self):
        data = os.urandom(2_000_000)
        cid = _KUBO.add_bytes(data, pin=False)
        with IPFSNode(peers=[self.addr], listen=[]) as node:
            self.assertEqual(node.cat(cid), data)

    def test_kubo_fetches_from_us(self):
        data = os.urandom(600_000)
        with IPFSNode(peers=[self.addr]) as node:
            cid = node.add_bytes(data, cid_version=1)
            self.assertEqual(_KUBO.cat(str(cid)), data)

    def test_trustless_gateway(self):
        data = b"gateway block test " + os.urandom(16)
        cid = _KUBO.add_bytes(data, cid_version=1, pin=False)
        gw = GatewayClient(API.replace(":5001", ":8080"))
        self.assertEqual(gw.get_block(cid), data)

    def test_ping_identify(self):
        with IPFSNode(peers=[self.addr], listen=[]) as node:
            self.assertTrue(node.ping(_KUBO_ID, 2))
            info = node.host.identify(_KUBO_ID)
            self.assertIn("/ipfs/bitswap/1.2.0", info.protocols)


if __name__ == "__main__":
    unittest.main()
