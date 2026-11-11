"""Snapshot of the embedded basilisk-ipfs node for the IPFS status page.

Each section is gathered on its own, so one failing subsystem (or one that is
switched off) shows up as an error or ``None`` instead of breaking the page.
basilisk-ipfs keeps some of this state in private attributes; it is only read here.
"""

import time


def _s(x):
    return None if x is None else str(x)


def _section(fn):
    try:
        return fn()
    except Exception as e:  # report, don't fail the whole page
        return {"error": f"{type(e).__name__}: {e}"}


def snapshot(explorer):
    node = explorer.node
    host = getattr(node, "host", None)
    now = time.time()
    if host is None:
        return {"available": False}
    am = host.addr_manager

    def node_info():
        from basilisk_ipfs import crypto
        from basilisk_ipfs.p2p import host as hostmod
        return {
            "peer_id": str(node.peer_id),
            "agent_version": hostmod.AGENT_VERSION,
            "protocol_version": hostmod.PROTOCOL_VERSION,
            "key_type": type(node.identity).__name__.replace("PrivateKey", ""),
            "crypto_backend": crypto.BACKEND,
            "uptime": now - explorer.started_at,
            "repo": node.repo,
            "protocols": host.protocols(),
        }

    def addresses():
        peer = str(node.peer_id)
        return {
            "reachability": host.reachability,
            "listen": [_s(a) for a in host.listen_addrs],
            "announced": [f"{a}/p2p/{peer}" if "p2p-circuit" not in str(a) else _s(a) for a in host.addrs()],
            "public": [_s(a) for a in host.public_addrs()],
            "observed": [_s(a) for a in am.observed_addrs(include_unconfirmed=True)],
            "nat_mapped": [_s(a) for a in getattr(am, "_nat", [])],
            "relay": [_s(a) for a in am.relay_addrs()],
            "verified": sorted(_s(a) for a in getattr(am, "_verified", ())),
            "unreachable": sorted(_s(a) for a in getattr(am, "_unreachable", ())),
        }

    def peers():
        rows = []
        for c in host.connections():
            pi = host.peerstore.get(c.remote_peer)
            rows.append({
                "peer": str(c.remote_peer),
                "addr": _s(c.remote_addr),
                "direction": c.direction,
                "relayed": bool(c.relayed),
                "limited": bool(c.limited),
                "age": now - c.opened,
                "agent": pi.agent_version if pi else None,
                "dht": bool(node.dht and c.remote_peer in node.dht.table),
            })
        rows.sort(key=lambda r: r["age"])
        return {
            "total": len({r["peer"] for r in rows}),
            "connections": len(rows),
            "inbound": sum(r["direction"] == "inbound" for r in rows),
            "outbound": sum(r["direction"] == "outbound" for r in rows),
            "relayed": sum(r["relayed"] for r in rows),
            "known": len(host.peerstore),
            "list": rows,
        }

    def dht():
        d = node.dht
        if d is None:
            return None
        return {"protocol": d.protocol, "routing_table": len(d.table),
                "bootstrap_peers": len(d.bootstrap_addrs), "mode": "client"}

    def bitswap():
        bs = node.bitswap
        wanting = {str(p): len(w) for p, w in list(bs.ledger.items()) if w}
        return {"stats": dict(bs.stats), "serving": bs.serve,
                "our_wants": len(bs._wants), "peers_wanting": len(wanting),
                "blocks_wanted_by_peers": sum(wanting.values())}

    def repo():
        st = node.repo_stat()
        st["pins"] = len(node.pin_ls())
        return st

    def block_cache():
        return explorer.block_cache.stats()

    def nat():
        n = node.nat
        if n is None:
            return None
        gw = n.gateway
        return {"gateway": type(gw).__name__.replace("Gateway", "") if gw else None,
                "gateway_host": _s(getattr(gw, "host", None)),
                "external_ip": n.external_ip,
                "mappings": [{"internal": i, "external": e[0] if isinstance(e, tuple) else e}
                             for i, e in n.mappings.items()]}

    def autonat():
        a = node.autonat
        if a is None:
            return None
        results = []
        for addr, res in list(a._results.items()):
            ok = sum(1 for _, r in res if r)
            results.append({"addr": _s(addr), "reachable": ok, "unreachable": len(res) - ok})
        return {"confidence": a.confidence, "results": results}

    def relay():
        r = node.relay
        if r is None:
            return None
        res = []
        for pid, rv in list(r.reservations.items()):
            res.append({"relay": str(pid), "expires_in": (rv.expire - now) if rv.expire else None,
                        "addrs": [_s(x) for x in (rv.addrs or [])][:3]})
        return {"mode": "always" if r.auto == "always" else ("auto" if r.auto else "static"),
                "reservations": res, "service": node.relay_service is not None}

    def hole_punch():
        hp = node.hole_punch
        return None if hp is None else dict(hp.stats)

    def ipns():
        # "Previous root" comes from the root block, but only if it's already
        # stored locally: fetching it here would stall the status page for up
        # to the fetch timeout on a fresh node.
        prev = None
        has = getattr(node, "block_has", None)
        if explorer.root and has and has(explorer.root):
            try:
                prev = explorer.catalog().inode(explorer.root, "").get("previous")
            except Exception:
                pass
        return {"name": explorer.ipns_name, "root": explorer.root, "sequence": explorer.root_seq,
                "previous": prev,
                "resolved_ago": (now - explorer.resolved_at) if explorer.resolved_at else None,
                "next_check_in": explorer.next_resolve_in(),
                "resolve_error": explorer.resolve_error}

    def sharing():
        # Announcing is done by basilisk-ipfs' provider; this only reports on it.
        pr = getattr(node, "provider", None)
        if pr is None:
            return None
        from basilisk_ipfs.cid import CID
        st = pr.status()
        keys = pr.keys()
        due = set(pr.due(keys, now=now))
        rows = []
        for mh in keys:
            last = pr.state.get(mh)
            fail = pr._failures.get(mh)
            rows.append({
                "cid": str(CID(1, "raw", mh)),
                "announced_ago": (now - last) if last else None,
                "next_in": max(0.0, last + pr.interval - now) if last else None,
                "due": mh in due,
                "failures": fail[0] if fail else 0,
                "retry_in": max(0.0, fail[1] - now) if fail else None,
            })
        rows.sort(key=lambda r: (r["announced_ago"] is not None, r["announced_ago"] or 0))
        return {
            "strategy": st["strategy"], "interval": st["interval"], "workers": pr.workers,
            "blocks": st["keys"], "announced": sum(1 for r in rows if r["announced_ago"] is not None),
            "due": st["due"], "retrying": st["retrying"],
            "passes": st["passes"], "provided_total": st["provided"], "failed_total": st["failed"],
            "last_pass_ago": (now - st["last_pass"]) if st["last_pass"] else None,
            "last_pass_duration": st["last_pass_duration"],
            "ready": bool(pr._addresses_ready()),
            "list": rows[:500],
        }

    return {
        "available": True,
        "node": _section(node_info),
        "addresses": _section(addresses),
        "ipns": _section(ipns),
        "sharing": _section(sharing),
        "peers": _section(peers),
        "dht": _section(dht),
        "bitswap": _section(bitswap),
        "repo": _section(repo),
        "block_cache": _section(block_cache),
        "nat": _section(nat),
        "autonat": _section(autonat),
        "relay": _section(relay),
        "hole_punch": _section(hole_punch),
    }
