"""Public-address discovery and announcement: Identify observed addresses,
AutoNAT v2, identify push, UPnP IGD and NAT-PMP (against simulated gateways)."""

import http.server
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import Host, Multiaddr
from basilisk_ipfs.nat import NATManager, NATPMPGateway, UPnPGateway
from basilisk_ipfs.p2p import autonat
from basilisk_ipfs.p2p.addrs import PRIVATE, PUBLIC


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class FakeConn:
    def __init__(self, peer, remote, local):
        self.remote_peer = peer
        self.remote_addr = Multiaddr(remote)
        self.local_addr = Multiaddr(local)


class TestAddressManager(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.host.listen("/ip4/0.0.0.0/tcp/0")
        self.port = self.host.listen_addrs[0].tcp_target()[1]
        self.am = self.host.addr_manager

    def tearDown(self):
        self.host.close()

    def observe(self, n, local_port=None, observed="/ip4/52.0.0.7/tcp/{port}", base=1):
        from basilisk_ipfs import Ed25519PrivateKey
        for i in range(n):
            conn = FakeConn(Ed25519PrivateKey().peer_id(), f"/ip4/8.8.{base}.{i + 1}/tcp/4001",
                            f"/ip4/192.168.0.2/tcp/{local_port or self.port}")
            self.am.record_observation(conn, Multiaddr(observed.format(port=self.port)))

    def test_observed_needs_four_distinct_observers(self):
        self.observe(3)
        self.assertEqual(self.am.observed_addrs(), [])
        self.observe(1, base=2)
        self.assertEqual([str(a) for a in self.am.observed_addrs()], [f"/ip4/52.0.0.7/tcp/{self.port}"])
        self.assertEqual(str(self.host.addrs()[0]), f"/ip4/52.0.0.7/tcp/{self.port}")

    def test_observations_from_ephemeral_ports_ignored(self):
        self.observe(6, local_port=55555)
        self.assertEqual(self.am.observed_addrs(True), [])

    def test_private_observations_ignored(self):
        self.observe(6, observed="/ip4/10.1.2.3/tcp/{port}")
        self.assertEqual(self.am.observed_addrs(True), [])

    def test_unreachable_addresses_withdrawn(self):
        self.observe(4)
        public = self.am.observed_addrs()[0]
        self.am.set_reachability(PRIVATE, (), [public])
        self.assertNotIn(public, self.host.addrs())
        self.am.set_reachability(PUBLIC, [public])
        self.assertEqual(self.host.addrs()[0], public)

    def test_announce_options(self):
        h = Host(announce=["/ip4/1.2.3.4/tcp/4001"], append_announce=["/dns4/example.com/tcp/4001"])
        self.assertEqual([str(a) for a in h.addrs()], ["/ip4/1.2.3.4/tcp/4001", "/dns4/example.com/tcp/4001"])
        h2 = Host(no_announce=["127.0.0.0/8", "/ip4/192.168.0.0/ipcidr/16"])
        h2.listen("/ip4/0.0.0.0/tcp/0")
        for a in h2.addrs():
            self.assertFalse(a.parts[0][1].startswith(("127.", "192.168.")), a)
        h.close()
        h2.close()


class TestAutoNATv2(unittest.TestCase):
    def setUp(self):
        self.server = Host()
        self.server.listen("/ip4/0.0.0.0/tcp/0")
        self.service = autonat.AutoNATService(self.server, allow_private=True, per_peer_interval=0,
                                              dial_data=(30_000, 30_000))
        self.client = Host()
        self.client.listen("/ip4/0.0.0.0/tcp/0")
        self.nat = autonat.AutoNATClient(self.client, start=False)
        sport = self.server.listen_addrs[0].tcp_target()[1]
        self.client.connect(f"/ip4/127.0.0.1/tcp/{sport}/p2p/{self.server.peer_id}")
        self.cport = self.client.listen_addrs[0].tcp_target()[1]

    def tearDown(self):
        self.client.close()
        self.server.close()

    def test_reachable(self):
        self.assertTrue(self.nat.check_address(self.server.peer_id, f"/ip4/127.0.0.1/tcp/{self.cport}"))

    def test_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        self.assertFalse(self.nat.check_address(self.server.peer_id, f"/ip4/127.0.0.1/tcp/{closed}"))

    def test_dial_data_when_ip_differs(self):
        # the server observes us as 127.0.0.1, so dialing 127.0.0.2 costs dial data first
        self.assertTrue(self.nat.check_address(self.server.peer_id, f"/ip4/127.0.0.2/tcp/{self.cport}"))

    def test_ok_without_nonce_is_discarded(self):
        self.service._dial_back = lambda addr, conn, nonce: autonat.DIAL_OK  # lying server
        self.assertIsNone(self.nat.check_address(self.server.peer_id, f"/ip4/127.0.0.1/tcp/{self.cport}"))

    def test_refused_when_no_acceptable_address(self):
        self.assertIsNone(self.nat.check_address(self.server.peer_id, "/ip6/::1/tcp/1"))

    def test_confidence(self):
        addr = Multiaddr("/ip4/198.51.100.1/tcp/1")
        for i, srv in enumerate(["a", "b"]):
            self.nat._record(addr, srv, True)
        self.assertEqual(self.nat.status_of(addr), "unknown")
        self.nat._record(addr, "c", True)
        self.assertEqual(self.nat.status_of(addr), PUBLIC)


class TestIdentifyPush(unittest.TestCase):
    def test_new_address_pushed_to_peers(self):
        a, b = Host(), Host()
        try:
            port = a.listen("/ip4/127.0.0.1/tcp/0").tcp_target()[1]
            b.connect(f"/ip4/127.0.0.1/tcp/{port}/p2p/{a.peer_id}")
            self.assertTrue(wait_for(lambda: "/ipfs/id/push/1.0.0" in a.peer_info(b.peer_id).protocols))
            new = Multiaddr("/ip4/1.2.3.4/tcp/4001")
            a.addr_manager.set_nat_addrs([new])
            self.assertTrue(wait_for(lambda: new in b.peer_info(a.peer_id).addrs))
        finally:
            a.close()
            b.close()


# ---- simulated gateways ------------------------------------------------------
DESC = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
 <deviceList><device><deviceList><device><serviceList><service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <controlURL>/ctl</controlURL>
 </service></serviceList></device></deviceList></device></deviceList>
</device></root>"""


class FakeIGD(http.server.BaseHTTPRequestHandler):
    mappings = {}
    calls = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(DESC)

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        action = self.headers["SOAPAction"].strip('"').split("#")[1]
        FakeIGD.calls.append(action)
        env = ('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{}'
               '</s:Body></s:Envelope>')
        if action == "GetExternalIPAddress":
            return self._reply(200, env.format(
                '<u:GetExternalIPAddressResponse xmlns:u="x"><NewExternalIPAddress>1.2.3.4'
                "</NewExternalIPAddress></u:GetExternalIPAddressResponse>"))
        if action == "AddPortMapping":
            if "<NewLeaseDuration>0<" not in body:  # only permanent leases supported
                return self._reply(500, env.format("<s:Fault><detail><UPnPError><errorCode>725"
                                                   "</errorCode></UPnPError></detail></s:Fault>"))
            port = int(body.split("<NewExternalPort>")[1].split("<")[0])
            FakeIGD.mappings[port] = body
            return self._reply(200, env.format("<u:AddPortMappingResponse xmlns:u='x'/>"))
        if action == "DeletePortMapping":
            port = int(body.split("<NewExternalPort>")[1].split("<")[0])
            FakeIGD.mappings.pop(port, None)
            return self._reply(200, env.format("<u:DeletePortMappingResponse xmlns:u='x'/>"))
        self._reply(500, "")


class TestUPnP(unittest.TestCase):
    def setUp(self):
        FakeIGD.mappings.clear()
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeIGD)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.loc = f"http://127.0.0.1:{self.srv.server_port}/desc.xml"

    def tearDown(self):
        self.srv.shutdown()

    def test_gateway_and_manager(self):
        gw = UPnPGateway.from_location(self.loc)
        self.assertTrue(gw.control_url.endswith("/ctl"))
        self.assertEqual(gw.external_ip(), "1.2.3.4")
        h = Host()
        port = h.listen("/ip4/0.0.0.0/tcp/0").tcp_target()[1]
        nm = NATManager(h, gateway=gw)
        try:
            want = Multiaddr(f"/ip4/1.2.3.4/tcp/{port}")
            self.assertTrue(wait_for(lambda: want in h.addrs()))
            self.assertIn(port, FakeIGD.mappings)  # retried with a permanent lease
        finally:
            nm.close()
            h.close()
        self.assertNotIn(port, FakeIGD.mappings)


class FakeNATPMP(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.mappings = {}
        self.start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(64)
            except OSError:
                return
            if data[:2] == b"\x00\x00":
                self.sock.sendto(struct.pack(">BBHI4s", 0, 128, 0, 1, socket.inet_aton("1.2.3.4")), addr)
            elif data[1] == 2:
                _, _, _, internal, external, life = struct.unpack(">BBHHHI", data[:12])
                if life == 0:
                    self.mappings.pop(internal, None)
                    external = 0
                else:
                    self.mappings[internal] = external
                self.sock.sendto(struct.pack(">BBHIHHI", 0, 130, 0, 1, internal, external, life), addr)


class TestNATPMP(unittest.TestCase):
    def test_map_and_delete(self):
        fake = FakeNATPMP()
        gw = NATPMPGateway.discover("127.0.0.1", port=fake.port)
        self.assertIsNotNone(gw)
        self.assertEqual(gw.external_ip(), "1.2.3.4")
        self.assertEqual(gw.add_mapping(4001, 4001, 7200), (4001, 7200))
        self.assertEqual(fake.mappings, {4001: 4001})
        gw.delete_mapping(4001, 4001)
        self.assertEqual(fake.mappings, {})
        fake.sock.close()


if __name__ == "__main__":
    unittest.main()
