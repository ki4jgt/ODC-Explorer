"""Address management: decide which addresses a host announces.

Sources, combined in :meth:`AddressManager.addrs`:

* **interface** – listen addresses expanded to the machine's IPs;
* **nat** – external addresses mapped on the router (UPnP / NAT-PMP);
* **observed** – our public address as reported by peers in the Identify
  ``observedAddr`` field. Observations only count from connections whose
  local end is one of our listen addresses (outbound dials reuse the listen
  port, so the observed port is the NAT's mapping of it). An address is
  activated once ``observed_threshold`` (default 4, as in go-libp2p)
  distinct observers report it, observers being grouped by IPv4 address or
  IPv6 /56;
* **verified** – addresses an AutoNAT v2 server successfully dialed back;
* **relay** – ``<relay>/p2p-circuit`` addresses from Circuit Relay v2
  reservations (AutoRelay), used when we are not directly reachable.

AutoNAT v2 results also prune the list: addresses that dial-backs showed to
be unreachable are not announced (unless ``announce_unreachable``).

``announce`` replaces everything, ``append_announce`` adds to it and
``no_announce`` filters it, like Kubo's ``Addresses.Announce``,
``AppendAnnounce`` and ``NoAnnounce``.
"""

import ipaddress
import logging
import threading
import time

from ..multiaddr import Multiaddr

log = logging.getLogger(__name__)

OBSERVATION_TTL = 3600.0
UNKNOWN, PUBLIC, PRIVATE = "unknown", "public", "private"


def ip_of(ma: Multiaddr):
    """The IP address object of an /ip4 or /ip6 multiaddr, else None."""
    if not ma.parts or ma.parts[0][0] not in ("ip4", "ip6"):
        return None
    try:
        return ipaddress.ip_address(ma.parts[0][1])
    except ValueError:
        return None


def is_public(ma: Multiaddr) -> bool:
    ip = ip_of(ma)
    if ip is None:  # DNS names are assumed public
        return bool(ma.parts) and ma.parts[0][0] in ("dns", "dns4", "dns6")
    return ip.is_global


def _parse_filter(f):
    """Accept '10.0.0.0/8', '/ip4/10.0.0.0/ipcidr/8' or a full multiaddr."""
    if isinstance(f, str) and not f.startswith("/"):
        return ipaddress.ip_network(f, strict=False)
    ma = Multiaddr(f)
    protos = ma.protocols()
    if len(protos) == 2 and protos[1] == "ipcidr":
        return ipaddress.ip_network(f"{ma.parts[0][1]}/{ma.parts[1][1]}", strict=False)
    return ma


class AddressManager:
    def __init__(self, host, announce=None, append_announce=(), no_announce=(),
                 observed_threshold=4, announce_unreachable=False):
        self.host = host
        self.announce = None if announce is None else [Multiaddr(a) for a in announce]
        self.append_announce = [Multiaddr(a) for a in append_announce]
        self.no_announce = [_parse_filter(f) for f in no_announce]
        self.observed_threshold = observed_threshold
        self.announce_unreachable = announce_unreachable
        self._lock = threading.Lock()
        self._observed = {}         # PeerID -> (Multiaddr, observer_ip, timestamp)
        self._nat = []              # external addrs mapped on the router
        self._relay = []            # <relay addr>/p2p/<relay>/p2p-circuit
        self._verified = set()      # addrs AutoNAT confirmed reachable
        self._unreachable = set()   # addrs AutoNAT could not dial
        self.reachability = UNKNOWN
        self._listeners = []        # callbacks run when addrs() changes
        self._last = None

    # ---- inputs ------------------------------------------------------------
    def record_observation(self, conn, observed: Multiaddr):
        """Remember how ``conn``'s remote peer sees us (Identify observedAddr)."""
        if observed.tcp_target() is None or not is_public(observed):
            return
        local = getattr(conn, "local_addr", None)
        if local is None or local.tcp_target() is None:
            return
        fam = 6 if local.protocols()[0] == "ip6" else 4
        if local.tcp_target()[1] not in self.listen_ports(fam):
            return  # ephemeral source port: the observed port means nothing
        observer = ip_of(conn.remote_addr) if conn.remote_addr else None
        if observer is None or not observer.is_global:
            return  # LAN peers can't tell us our public address
        group = (str(ipaddress.ip_network(f"{observer}/56", strict=False))
                 if observer.version == 6 else str(observer))
        with self._lock:
            self._observed[conn.remote_peer] = (observed, group, time.time())
        self._check_changed()

    def set_nat_addrs(self, addrs):
        with self._lock:
            self._nat = [Multiaddr(a) for a in addrs]
        self._check_changed()

    def set_relay_addrs(self, addrs):
        with self._lock:
            self._relay = [Multiaddr(a) for a in addrs]
        self._check_changed()

    def relay_addrs(self):
        with self._lock:
            return list(self._relay)

    def set_reachability(self, status, reachable=(), unreachable=()):
        with self._lock:
            self.reachability = status
            self._verified = {Multiaddr(a) for a in reachable}
            self._unreachable = {Multiaddr(a) for a in unreachable} - self._verified
        log.info("reachability: %s %s", status, [str(a) for a in reachable])
        self._check_changed()

    def on_change(self, cb):
        self._listeners.append(cb)

    # ---- derived -----------------------------------------------------------
    def listen_ports(self, family=4):
        out = []
        for a in self.host.listen_addrs:
            if (a.protocols()[0] == "ip6") == (family == 6):
                out.append(a.tcp_target()[1])
        return out

    def interface_addrs(self):
        from .host import _local_ips
        out = []
        for a in self.host.listen_addrs:
            ip, port = a.tcp_target()
            if ip in ("0.0.0.0", "::"):
                for local in _local_ips(6 if ip == "::" else 4):
                    out.append(Multiaddr(f"/ip{6 if ':' in local else 4}/{local}/tcp/{port}"))
            else:
                out.append(a)
        return out

    def observed_addrs(self, include_unconfirmed=False):
        """Observed public addresses that ``observed_threshold`` distinct
        observer groups agree on."""
        now = time.time()
        votes = {}
        with self._lock:
            for peer, (ma, observer, ts) in list(self._observed.items()):
                if now - ts > OBSERVATION_TTL:
                    del self._observed[peer]
                    continue
                votes.setdefault(ma, set()).add(observer)
        return [ma for ma, groups in votes.items()
                if include_unconfirmed or len(groups) >= self.observed_threshold]

    def candidates(self):
        """Public addresses to verify with AutoNAT: activated observed
        addresses, router mappings and public interface addresses."""
        with self._lock:
            out = list(self._nat)
        out += self.observed_addrs()
        out += [a for a in self.interface_addrs() if is_public(a)]
        return list(dict.fromkeys(out))

    def _filtered(self, addrs):
        out = []
        for a in addrs:
            ip = ip_of(a)
            blocked = False
            for f in self.no_announce:
                if isinstance(f, Multiaddr):
                    blocked = f == a
                elif ip is not None and ip.version == f.version:
                    blocked = ip in f
                if blocked:
                    break
            if not blocked:
                out.append(a)
        return list(dict.fromkeys(out))

    def addrs(self):
        """The addresses we announce, best (public) first."""
        if self.announce is not None:
            return self._filtered(self.announce + self.append_announce)
        with self._lock:
            nat = list(self._nat)
            verified = list(self._verified)
            unreachable = set(self._unreachable)
        public = verified + nat + self.observed_addrs()
        if not self.announce_unreachable:
            public = [a for a in public if a not in unreachable]
        local = self.interface_addrs()
        local = [a for a in local if self.announce_unreachable or a not in unreachable]
        return self._filtered(public + self.relay_addrs() + local + self.append_announce)

    def public_addrs(self):
        return [a for a in self.addrs() if is_public(a)]

    def _check_changed(self):
        current = self.addrs()
        with self._lock:
            if current == self._last:
                return
            self._last = current
        log.info("announced addresses changed: %s", [str(a) for a in current])
        for cb in list(self._listeners):
            try:
                cb(current)
            except Exception:
                log.exception("address change callback failed")
