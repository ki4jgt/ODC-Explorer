"""Minimal DNS TXT resolver (the stdlib only resolves A/AAAA), used for
``/dnsaddr`` multiaddrs and DNSLink."""

import os
import random
import socket
import struct

from .multiaddr import Multiaddr

FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8"]


def _nameservers():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers + FALLBACK_SERVERS


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna") if label else b""
        if len(b) > 63:
            raise ValueError("DNS label too long")
        out += bytes([len(b)]) + b
    return out + b"\0"


def _skip_name(buf, off):
    while True:
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def _query(server, name, qtype, timeout):
    qid = random.getrandbits(16)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", qtype, 1)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        while True:
            resp, _ = s.recvfrom(65535)
            if len(resp) >= 12 and struct.unpack(">H", resp[:2])[0] == qid:
                break
    if resp[2] & 0x02:  # truncated: retry over TCP
        with socket.create_connection((server, 53), timeout) as s:
            s.sendall(struct.pack(">H", len(q)) + q)
            ln = struct.unpack(">H", _recv_exact(s, 2))[0]
            resp = _recv_exact(s, ln)
    return resp


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("DNS TCP connection closed")
        buf += chunk
    return buf


def resolve_txt(name: str, timeout=5.0):
    """Return the TXT strings for ``name`` (each record's chunks joined)."""
    last = None
    for server in _nameservers():
        try:
            resp = _query(server, name, 16, timeout)
        except (OSError, EOFError) as e:
            last = e
            continue
        rcode = resp[3] & 0x0F
        if rcode == 3:
            return []
        if rcode != 0:
            last = OSError(f"DNS error rcode={rcode}")
            continue
        _, _, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
        off = 12
        for _ in range(qd):
            off = _skip_name(resp, off) + 4
        out = []
        for _ in range(an):
            off = _skip_name(resp, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
            off += 10
            rdata = resp[off:off + rdlen]
            off += rdlen
            if rtype == 16:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln])
                    i += 1 + ln
                out.append(b"".join(parts).decode(errors="replace"))
        return out
    raise OSError(f"TXT lookup for {name} failed: {last}")


def resolve_dnsaddr(addr, depth=0):
    """Expand a ``/dnsaddr/<domain>[/p2p/<id>]`` multiaddr into concrete multiaddrs."""
    ma = Multiaddr(addr)
    if ma.protocols()[0] != "dnsaddr":
        return [ma]
    if depth > 4:
        return []
    want = ma.peer_id
    out = []
    for txt in resolve_txt("_dnsaddr." + ma.parts[0][1]):
        if not txt.startswith("dnsaddr="):
            continue
        try:
            sub = Multiaddr(txt[8:])
        except ValueError:
            continue
        if want is not None and sub.peer_id is not None and sub.peer_id != want:
            continue
        out.extend(resolve_dnsaddr(sub, depth + 1))
    return out


def resolve_dnslink(domain: str):
    """Return the DNSLink path (e.g. ``/ipfs/bafy...``) for ``domain`` or None."""
    for name in ("_dnslink." + domain, domain):
        for txt in resolve_txt(name):
            if txt.startswith("dnslink="):
                return txt[8:].strip()
    return None
