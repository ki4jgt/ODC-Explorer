"""Storage limit and automatic least-recently-used garbage collection."""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import CID, IPFSNode, StorageFull
from basilisk_ipfs.storage import parse_size

KB = 1000


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class TestStorageLimit(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(parse_size("10GB"), 10 * 10 ** 9)
        self.assertEqual(parse_size("512 MiB"), 512 * 2 ** 20)
        self.assertEqual(parse_size(1234), 1234)
        with self.assertRaises(ValueError):
            parse_size("ten gigs")

    def test_import_refused_when_pinned_data_fills_limit(self):
        with IPFSNode(offline=True, storage_max=100 * KB) as n:
            n.add_bytes(os.urandom(60 * KB))
            with self.assertRaises(StorageFull):
                n.add_bytes(os.urandom(60 * KB))
            self.assertLessEqual(n.repo_stat()["size"], 100 * KB)
            self.assertEqual(len(n.pin_ls()), 1)  # failed import was not pinned
            n.gc()  # leftovers of the failed import are collectable
            self.assertLessEqual(n.repo_stat()["size"], 61 * KB)

    def test_import_evicts_oldest_unpinned_first(self):
        with IPFSNode(offline=True, storage_max=100 * KB) as n:
            cids = []
            for i in range(4):  # 4 x 20KB unpinned "cache" blocks, oldest first
                cids.append(n.block_put(os.urandom(20 * KB)))
                time.sleep(0.01)
            n.block_get(cids[0])  # reading makes block 0 the most recently used
            pinned = n.add_bytes(os.urandom(30 * KB))  # needs room: 80 + 30 > 100
            self.assertTrue(n.block_has(pinned))
            self.assertTrue(n.block_has(cids[0]), "recently used block survived")
            self.assertFalse(n.block_has(cids[1]), "least recently used block evicted")
            self.assertLessEqual(n.repo_stat()["size"], 100 * KB)

    def test_background_gc_at_high_water(self):
        with IPFSNode(offline=True, storage_max=100 * KB) as n:
            keep = n.add_bytes(os.urandom(10 * KB))
            for _ in range(5):  # cache data that pushes past 90%
                n.blockstore.put_block(os.urandom(20 * KB))
                time.sleep(0.01)
            self.assertTrue(wait_for(lambda: n.repo_stat()["size"] <= 80 * KB))
            self.assertTrue(n.block_has(keep))
            self.assertGreater(n.repo_stat()["blocks_evicted"], 0)

    def test_pins_never_evicted(self):
        with IPFSNode(offline=True, storage_max=200 * KB) as n:
            pinned = n.add_bytes(os.urandom(150 * KB), chunk_size=10 * KB)
            for _ in range(10):
                n.blockstore.put_block(os.urandom(10 * KB))
            n.gc(target_size=0)
            self.assertEqual(len(n.cat(pinned)), 150 * KB)
            n.pin_rm(pinned)
            n.gc()
            self.assertEqual(n.repo_stat()["size"], 0)

    def test_limit_and_lru_survive_restart(self):
        tmp = tempfile.mkdtemp()
        try:
            with IPFSNode(tmp, offline=True) as n:
                old = n.block_put(os.urandom(40 * KB))
                time.sleep(0.05)
                new = n.block_put(os.urandom(40 * KB))
            with IPFSNode(tmp, offline=True, storage_max=100 * KB) as n:
                self.assertEqual(n.repo_stat()["size"], 80 * KB)
                n.add_bytes(os.urandom(30 * KB))
                self.assertFalse(n.block_has(old))
                self.assertTrue(n.block_has(new))
        finally:
            shutil.rmtree(tmp)

    def test_unlimited_by_default(self):
        with IPFSNode(offline=True) as n:
            for _ in range(3):
                n.block_put(os.urandom(50 * KB))
            self.assertEqual(n.repo_stat()["storage_max"], None)
            self.assertEqual(n.repo_stat()["num_blocks"], 3)


if __name__ == "__main__":
    unittest.main()
