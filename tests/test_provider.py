"""Reprovider (DHT provider records) and IPNS republisher."""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import IPFSNode, ipns
from basilisk_ipfs.provider import DEFAULT_INTERVAL, IPNSRepublisher, Provider


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class StubDHT:
    def __init__(self):
        self.calls = []
        self.fail = set()

    def __call__(self, cid):
        self.calls.append(cid.multihash)
        return 0 if cid.multihash in self.fail else 20


def make(node, strategy="all", path=None, clock=None, dht=None):
    return Provider(node, strategy, state_path=path, clock=clock or Clock(),
                    provide_fn=dht or StubDHT(), start=False)


class TestProvider(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.node = IPFSNode(self.tmp, offline=True)
        self.pinned = self.node.add_bytes(os.urandom(600_000), chunk_size=100_000)  # 7 blocks
        self.cached = self.node.block_put(b"unpinned block")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_strategies(self):
        all_keys = make(self.node, "all").keys()
        pinned = make(self.node, "pinned").keys()
        roots = make(self.node, "roots").keys()
        self.assertEqual(len(pinned), 7)
        self.assertIn(self.cached.multihash, all_keys)
        self.assertNotIn(self.cached.multihash, pinned)
        self.assertEqual(roots, {self.pinned.multihash})

    def test_reannounces_after_interval_only(self):
        clock, dht = Clock(), StubDHT()
        p = make(self.node, "pinned", clock=clock, dht=dht)
        self.assertEqual(p.run_once()["provided"], 7)
        self.assertEqual(p.run_once()["due"], 0)
        clock.now += DEFAULT_INTERVAL - 60
        self.assertEqual(p.run_once()["due"], 0)
        clock.now += 120
        self.assertEqual(p.run_once()["provided"], 7)
        self.assertEqual(len(dht.calls), 14)

    def test_state_survives_restart(self):
        path = os.path.join(self.tmp, "provider.sqlite")
        clock = Clock()
        p = make(self.node, "all", path, clock)
        self.assertEqual(p.run_once()["provided"], 8)
        p.close()
        p2 = make(self.node, "all", path, clock)
        self.assertEqual(p2.run_once()["due"], 0)  # nothing re-announced on restart
        clock.now += DEFAULT_INTERVAL + 1
        self.assertEqual(p2.run_once()["due"], 8)
        p2.close()

    def test_failures_retry_with_backoff(self):
        clock, dht = Clock(), StubDHT()
        dht.fail.add(self.pinned.multihash)
        p = make(self.node, "roots", clock=clock, dht=dht)
        self.assertEqual(p.run_once(), {"due": 1, "provided": 0, "failed": 1, "keys": 1})
        self.assertEqual(p.run_once()["due"], 0)  # backing off
        clock.now += 61
        dht.fail.clear()
        self.assertEqual(p.run_once()["provided"], 1)
        self.assertEqual(p.status()["retrying"], 0)

    def test_gc_and_unpin_forget_keys(self):
        p = make(self.node, "all")
        p.run_once()
        self.node.gc()  # removes the unpinned block
        p.run_once()
        self.assertNotIn(self.cached.multihash, p.state.keys())
        self.assertEqual(len(p.state), 7)

    def test_new_content_is_due(self):
        p = make(self.node, "all")
        p.run_once()
        new = self.node.add_bytes(b"fresh content")
        self.assertEqual(p.due(), [new.multihash])


class TestIPNSRepublish(unittest.TestCase):
    def test_persist_and_republish(self):
        tmp = tempfile.mkdtemp()
        try:
            with IPFSNode(tmp, offline=True) as n:
                cid = n.add_bytes(b"site v1")
                name, rec = n.name_publish(cid)
                self.assertEqual(rec.sequence, 0)
            with IPFSNode(tmp, offline=True) as n:  # restart
                self.assertEqual(n.name_resolve(name), f"/ipfs/{cid}")
                r = IPNSRepublisher(n, period=0, start=False)
                n._ipns_published[name]["published"] -= 10
                old_validity = n._local_records[name].validity
                time.sleep(0.01)
                self.assertEqual(r.run_once(), [name])
                new = n._local_records[name]
                self.assertEqual(new.sequence, 1)            # sequence continues
                self.assertEqual(new.path, f"/ipfs/{cid}")   # same target
                self.assertGreater(new.validity, old_validity)
                self.assertTrue(ipns.Record.decode(new.encode()).verify(name))
            with IPFSNode(tmp, offline=True) as n:
                _, rec = n.name_publish(cid)
                self.assertEqual(rec.sequence, 2)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
