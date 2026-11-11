"""Router port mapping, as Kubo does (``Swarm.DisableNatPortMap``):

* UPnP IGD (WANIPConnection / WANPPPConnection v1 and v2) via SSDP + SOAP
* NAT-PMP (RFC 6886)

:class:`NATManager` maps each TCP listen port, renews the lease, reports the
external addresses to the host's address manager (they are then verified with
AutoNAT like any other candidate) and removes the mappings on close.
"""

import ipaddress
import logging
import random
import re
import socket
import struct
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .multiaddr import Multiaddr

log = logging.getLogger(__name__)

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_TARGETS = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
NATPMP_PORT = 5351


class NATError(Exception):
    pass


def default_gateway():
    """IPv4 default gateway from the Linux routing table, or None."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except (OSError, ValueError, IndexError):
        pass
    return None


def local_ip_towards(host):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 9))
        return s.getsockname()[0]


def _local(tag):
    return tag.rsplit("}", 1)[-1]


# ---- UPnP IGD -------------------------------------------------------------
class UPnPGateway:
    method = "upnp"

    def __init__(self, control_url, service_type, timeout=5.0):
        self.control_url = control_url
        self.service_type = service_type
        self.timeout = timeout
        self.host = urllib.parse.urlparse(control_url).hostname

    @classmethod
    def discover(cls, timeout=3.0):
        """Find a gateway with SSDP M-SEARCH. Returns a gateway or None."""
        locations = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(timeout)
            for st in SSDP_TARGETS:
                msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                       f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n')
                try:
                    s.sendto(msg.encode(), SSDP_ADDR)
                except OSError as e:
                    log.debug("SSDP send failed: %s", e)
                    return None
            try:
                while True:
                    data, _ = s.recvfrom(4096)
                    m = re.search(rb"(?im)^location:\s*(\S+)", data)
                    if m and m.group(1).decode() not in locations:
                        locations.append(m.group(1).decode())
            except socket.timeout:
                pass
        for loc in locations:
            try:
                return cls.from_location(loc)
            except Exception as e:
                log.debug("UPnP device at %s unusable: %s", loc, e)
        return None

    @classmethod
    def from_location(cls, location, timeout=5.0):
        """Build from a device description URL (the SSDP LOCATION header)."""
        xml = urllib.request.urlopen(location, timeout=timeout).read()
        root = ET.fromstring(xml)
        base = location
        for el in root.iter():
            if _local(el.tag) == "URLBase" and el.text and el.text.strip():
                base = el.text.strip()
        best = None
        for svc in root.iter():
            if _local(svc.tag) != "service":
                continue
            fields = {_local(c.tag): (c.text or "").strip() for c in svc}
            stype = fields.get("serviceType", "")
            if any(w in stype for w in WAN_SERVICES) and fields.get("controlURL"):
                cand = (stype, urllib.parse.urljoin(base, fields["controlURL"]))
                # prefer WANIPConnection over WANPPPConnection
                if best is None or ("WANIPConnection" in stype and "WANIPConnection" not in best[0]):
                    best = cand
        if best is None:
            raise NATError("no WAN connection service in device description")
        return cls(best[1], best[0], timeout)

    def _soap(self, action, args=()):
        body = "".join(f"<{k}>{v}</{k}>" for k, v in args)
        envelope = ('<?xml version="1.0"?>'
                    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                    f'<u:{action} xmlns:u="{self.service_type}">{body}</u:{action}>'
                    "</s:Body></s:Envelope>").encode()
        req = urllib.request.Request(self.control_url, data=envelope, method="POST", headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{self.service_type}#{action}"'})
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout).read()
        except urllib.error.HTTPError as e:
            text = e.read()
            code = re.search(rb"<(?:\w+:)?errorCode>\s*(\d+)", text)
            desc = re.search(rb"<(?:\w+:)?errorDescription>([^<]*)", text)
            raise NATError(f"{action} failed: UPnP error {code.group(1).decode() if code else e.code} "
                           f"{desc.group(1).decode() if desc else ''}".strip()) from None
        out = {}
        for el in ET.fromstring(resp).iter():
            if el.text is not None:
                out[_local(el.tag)] = el.text.strip()
        return out

    def external_ip(self):
        return self._soap("GetExternalIPAddress")["NewExternalIPAddress"]

    def add_mapping(self, internal_port, external_port, lifetime, description="basilisk-ipfs"):
        """Map TCP ``external_port`` -> this host's ``internal_port``.
        Returns ``(external_port, lifetime)`` actually granted."""
        client = local_ip_towards(self.host)
        tries = [external_port] + [random.randint(10000, 60000) for _ in range(3)]
        for ext in tries:
            for lease in (lifetime, 0):  # some IGDs only allow permanent (0) leases
                try:
                    self._soap("AddPortMapping", [
                        ("NewRemoteHost", ""), ("NewExternalPort", ext), ("NewProtocol", "TCP"),
                        ("NewInternalPort", internal_port), ("NewInternalClient", client),
                        ("NewEnabled", 1), ("NewPortMappingDescription", description),
                        ("NewLeaseDuration", lease)])
                    return ext, lease
                except NATError as e:
                    msg = str(e)
                    if "725" in msg and lease:      # OnlyPermanentLeasesSupported
                        continue
                    if "718" in msg:                # ConflictInMappingEntry
                        break
                    raise
        raise NATError("no free external port")

    def delete_mapping(self, external_port):
        self._soap("DeletePortMapping", [("NewRemoteHost", ""), ("NewExternalPort", external_port),
                                         ("NewProtocol", "TCP")])


# ---- NAT-PMP (RFC 6886) ---------------------------------------------------
class NATPMPGateway:
    method = "nat-pmp"

    def __init__(self, gateway, port=NATPMP_PORT, timeout=0.25, retries=4):
        self.host = gateway
        self.port = port
        self.timeout = timeout
        self.retries = retries

    @classmethod
    def discover(cls, gateway=None, **kw):
        gateway = gateway or default_gateway()
        if not gateway:
            return None
        gw = cls(gateway, **kw)
        try:
            gw.external_ip()
            return gw
        except (NATError, OSError) as e:
            log.debug("NAT-PMP not available at %s: %s", gateway, e)
            return None

    def _request(self, payload, expect_op):
        # RFC 6886 3.1: retransmit starting at 250 ms, doubling each time
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((self.host, self.port))
            timeout = self.timeout
            for _ in range(self.retries):
                s.send(payload)
                s.settimeout(timeout)
                try:
                    while True:
                        data = s.recv(64)
                        if len(data) >= 8 and data[0] == 0 and data[1] == expect_op:
                            result = struct.unpack(">H", data[2:4])[0]
                            if result != 0:
                                raise NATError(f"NAT-PMP result code {result}")
                            return data
                except socket.timeout:
                    timeout *= 2
        raise NATError("no NAT-PMP response")

    def external_ip(self):
        data = self._request(b"\x00\x00", 128)
        return socket.inet_ntoa(data[8:12])

    def add_mapping(self, internal_port, external_port, lifetime, description=None):
        req = struct.pack(">BBHHHI", 0, 2, 0, internal_port, external_port, lifetime)
        data = self._request(req, 130)
        _, _, _, _, internal, mapped, granted = struct.unpack(">BBHIHHI", data[:16])
        return mapped, granted

    def delete_mapping(self, external_port, internal_port=None):
        # RFC 6886 3.4: lifetime 0 and suggested external port 0 delete the mapping
        self._request(struct.pack(">BBHHHI", 0, 2, 0, internal_port or external_port, 0, 0), 130)


# ---- manager --------------------------------------------------------------
class NATManager:
    """Keeps router port mappings for the host's TCP listen ports."""

    def __init__(self, host, lifetime=3600, gateway=None):
        self.host = host
        self.lifetime = lifetime
        self.gateway = gateway
        self.mappings = {}  # internal_port -> (external_port, lease)
        self.external_ip = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="nat")
        self._thread.start()

    def _discover(self):
        return UPnPGateway.discover() or NATPMPGateway.discover()

    def _run(self):
        try:
            gw = self.gateway or self._discover()
        except Exception as e:
            log.debug("NAT discovery failed: %s", e)
            gw = None
        if gw is None:
            log.info("no UPnP or NAT-PMP gateway found; not mapping ports")
            return
        self.gateway = gw
        while not self._stop.is_set():
            lease = self._map_all()
            # renew at half the lease (permanent leases: re-check hourly)
            self._stop.wait(max(60, (lease or 7200) / 2))

    def _map_all(self):
        gw = self.gateway
        try:
            ext_ip = gw.external_ip()
            if not ipaddress.ip_address(ext_ip).is_global:
                log.warning("router's external address %s is not public (double NAT / CGNAT); "
                            "port mapping will not make this node reachable", ext_ip)
                self.host.addr_manager.set_nat_addrs([])
                return self.lifetime
        except Exception as e:
            log.warning("NAT gateway (%s) failed: %s", gw.method, e)
            return self.lifetime
        self.external_ip = ext_ip
        addrs, leases = [], []
        for a in self.host.listen_addrs:
            if a.protocols()[0] != "ip4":
                continue
            ip, port = a.tcp_target()
            if ipaddress.ip_address(ip).is_loopback:
                continue
            prev = self.mappings.get(port, (port, 0))[0]
            try:
                ext_port, lease = gw.add_mapping(port, prev, self.lifetime)
            except Exception as e:
                log.warning("could not map TCP port %d via %s: %s", port, gw.method, e)
                continue
            self.mappings[port] = (ext_port, lease)
            addrs.append(Multiaddr(f"/ip4/{ext_ip}/tcp/{ext_port}"))
            leases.append(lease)
            log.info("mapped %s -> local port %d via %s", addrs[-1], port, gw.method)
        self.host.addr_manager.set_nat_addrs(addrs)
        return min([l for l in leases if l] or [self.lifetime])

    def close(self):
        self._stop.set()
        if self.gateway is None:
            return
        for internal, (external, _) in list(self.mappings.items()):
            try:
                if isinstance(self.gateway, NATPMPGateway):
                    self.gateway.delete_mapping(external, internal)
                else:
                    self.gateway.delete_mapping(external)
            except Exception as e:
                log.debug("removing port mapping %d failed: %s", external, e)
        self.mappings.clear()
        self.host.addr_manager.set_nat_addrs([])
