"""Connection manager (Kubo-style trimming) and file-descriptor handling."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import Host
from basilisk_ipfs.p2p import connmgr
from basilisk_ipfs.p2p.connmgr import ConnectionManager
from basilisk_ipfs.p2p.host import DialError


class TestTrimming(unittest.TestCase):
    def setUp(self):
        self.hub = Host()
        port = self.hub.listen("/ip4/127.0.0.1/tcp/0").tcp_target()[1]
        self.cm = ConnectionManager(self.hub, low_water=2, high_water=4, grace_period=60,
                                    start=False)
        self.peers = []
        for _ in range(6):
            h = Host()
            h.connect(f"/ip4/127.0.0.1/tcp/{port}/p2p/{self.hub.peer_id}")
            self.peers.append(h)
        end = time.time() + 5
        while len(self.hub.connections()) < 6 and time.time() < end:
            time.sleep(0.02)

    def tearDown(self):
        for h in self.peers + [self.hub]:
            h.close()

    def ids(self):
        return [h.peer_id for h in self.peers]

    def age(self, seconds=120):
        """Make every connection look ``seconds`` old (no sleeping: deterministic)."""
        for c in self.hub.connections():
            c.opened -= seconds
            c.last_active -= seconds

    def test_grace_period_protects_new_connections(self):
        self.assertEqual(len(self.hub.connections()), 6)
        self.assertEqual(self.cm.trim(), 0)  # all younger than the grace period
        self.age()
        self.assertEqual(self.cm.trim(), 4)
        self.assertEqual(len(self.hub.connections()), 2)

    def test_protected_and_valuable_peers_survive(self):
        ids = self.ids()
        self.cm.protect(ids[0], "static")
        self.cm.tag_peer(ids[1], "bitswap", 10)
        self.age()
        self.cm.trim()
        left = {c.remote_peer for c in self.hub.connections()}
        self.assertEqual(left, {ids[0], ids[1]})

    def test_least_recently_used_goes_first(self):
        self.age()
        ids = self.ids()
        for c in self.hub.connections():  # make the last two the most recently active
            c.last_active = time.time() - (0 if c.remote_peer in ids[-2:] else 60)
        self.cm.trim()
        self.assertEqual({c.remote_peer for c in self.hub.connections()}, set(ids[-2:]))

    def test_unprotect(self):
        pid = self.ids()[0]
        self.cm.protect(pid, "a")
        self.cm.protect(pid, "b")
        self.assertTrue(self.cm.unprotect(pid, "a"))
        self.assertFalse(self.cm.unprotect(pid, "b"))
        self.assertFalse(self.cm.is_protected(pid))


class TestFileDescriptors(unittest.TestCase):
    def test_raise_fd_limit_never_lowers(self):
        try:
            import resource
        except ImportError:
            self.skipTest("no resource module")
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        result = connmgr.raise_fd_limit(16)  # lower than current: must not lower it
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE)[0], soft)
        self.assertEqual(result, soft)

    def test_dial_refused_near_fd_limit(self):
        h = Host()
        original = connmgr.fd_usage
        connmgr.fd_usage = lambda: (950, 1000)
        try:
            with self.assertRaisesRegex(DialError, "open-file limit"):
                h.connect("/ip4/127.0.0.1/tcp/9/p2p/12D3KooWJgwhiomKUyAcqdDSq2PaMA6uM8QTAuDAuSofYfy4X6Qe")
        finally:
            connmgr.fd_usage = original
            h.close()

    def test_no_dials_after_close(self):
        h = Host()
        h.close()
        with self.assertRaisesRegex(DialError, "closed"):
            h.connect("/ip4/127.0.0.1/tcp/9")


if __name__ == "__main__":
    unittest.main()
