"""Circuit Relay v2 and DCUtR between in-process hosts over loopback."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import Host, IPFSNode
from basilisk_ipfs.p2p.dcutr import HolePunchService
from basilisk_ipfs.p2p.host import LimitedConnectionError
from basilisk_ipfs.p2p.relay import RelayClient, RelayError, RelayService


def wait_for(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


class TestCircuitRelay(unittest.TestCase):
    def setUp(self):
        self.r, self.a, self.b = Host(), Host(), Host()
        for h in (self.r, self.a, self.b):
            h.listen("/ip4/0.0.0.0/tcp/0")
        RelayService(self.r)
        self.ra = RelayClient(self.a, auto=False)
        self.rb = RelayClient(self.b, auto=False)
        rport = self.r.listen_addrs[0].tcp_target()[1]
        self.relay_addr = f"/ip4/127.0.0.1/tcp/{rport}/p2p/{self.r.peer_id}"

    def tearDown(self):
        for h in (self.a, self.b, self.r):
            h.close()

    def test_reservation_and_announcement(self):
        res = self.rb.reserve(self.relay_addr)
        self.assertGreater(res.expire, time.time() + 3000)
        circuit = [a for a in self.b.addrs() if "p2p-circuit" in a.protocols()]
        self.assertTrue(circuit)
        self.assertTrue(all(str(a).endswith(f"/p2p/{self.r.peer_id}/p2p-circuit") for a in circuit))

    def test_relayed_connection_is_limited(self):
        self.rb.reserve(self.relay_addr)
        circuit = f"{self.relay_addr}/p2p-circuit"
        conn = self.ra.dial(circuit, self.b.peer_id)
        self.assertTrue(conn.limited)
        self.assertTrue(self.a.ping(self.b.peer_id, 2))  # allowed on limited conns
        self.assertIn("/ipfs/ping/1.0.0", self.a.identify(conn).protocols)
        with self.assertRaises(LimitedConnectionError):
            self.a.new_stream(conn, "/ipfs/bitswap/1.2.0")

    def test_no_reservation(self):
        with self.assertRaises(RelayError) as ctx:
            self.ra.dial(f"{self.relay_addr}/p2p-circuit", self.b.peer_id)
        self.assertIn("NO_RESERVATION", str(ctx.exception))

    def test_connect_peer_falls_back_to_circuit(self):
        self.rb.reserve(self.relay_addr)
        circuit = [a for a in self.b.addrs() if "p2p-circuit" in a.protocols()]
        conn = self.a.connect_peer(self.b.peer_id, [f"/ip4/127.0.0.1/tcp/1"] + circuit)
        self.assertTrue(conn.relayed)


class TestHolePunch(unittest.TestCase):
    def test_dcutr_upgrades_to_direct(self):
        r, a, b = Host(), Host(), Host()
        try:
            for h in (r, a, b):
                h.listen("/ip4/0.0.0.0/tcp/0")
            RelayService(r)
            ra, rb = RelayClient(a, auto=False), RelayClient(b, auto=False)
            hpa, hpb = HolePunchService(a), HolePunchService(b)
            rport = r.listen_addrs[0].tcp_target()[1]
            relay_addr = f"/ip4/127.0.0.1/tcp/{rport}/p2p/{r.peer_id}"
            rb.reserve(relay_addr)
            conn = ra.dial(f"{relay_addr}/p2p-circuit", b.peer_id)
            self.assertTrue(conn.limited)
            self.assertTrue(wait_for(lambda: any(not c.limited for c in a.connections(b.peer_id))),
                            "no direct connection after DCUtR")
            # streams now go over the direct connection
            st = a.new_stream(b.peer_id, "/ipfs/id/1.0.0")
            self.assertFalse(a.connections(b.peer_id)[0].limited)
            st.reset()
        finally:
            for h in (a, b, r):
                h.close()

    def test_node_fetch_through_relay_then_direct(self):
        with IPFSNode(listen=["/ip4/0.0.0.0/tcp/0"], relay_service=True, autonat=False,
                      nat_port_map=False) as relay, \
             IPFSNode(listen=["/ip4/0.0.0.0/tcp/0"], autonat=False, nat_port_map=False,
                      relay_client="always", static_relays=[relay.id()["Addresses"][0]]) as b, \
             IPFSNode(listen=["/ip4/0.0.0.0/tcp/0"], autonat=False, nat_port_map=False) as a:
            self.assertTrue(wait_for(lambda: b.relay.reservations))
            data = os.urandom(300_000)
            cid = b.add_bytes(data)
            circuit = [str(x) for x in b.host.addrs() if "p2p-circuit" in x.protocols()]
            a.host.add_addrs(b.peer_id, circuit)
            a.host.connect_peer(b.peer_id)
            self.assertTrue(wait_for(lambda: any(not c.limited for c in a.host.connections(b.peer_id))))
            self.assertEqual(a.cat(cid), data)


if __name__ == "__main__":
    unittest.main()
