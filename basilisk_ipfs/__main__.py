"""Minimal command line: ``python -m basilisk_ipfs <command> ...``"""

import argparse
import logging
import sys

from . import IPFSNode, Importer, MemoryBlockstore


def main(argv=None):
    ap = argparse.ArgumentParser(prog="basilisk-ipfs", description="Pure-Python IPFS")
    ap.add_argument("--repo", help="repository directory (default: in-memory)")
    ap.add_argument("--peer", action="append", default=[], help="multiaddr to connect to (repeatable)")
    ap.add_argument("--no-dht", action="store_true", help="do not use the public DHT")
    ap.add_argument("--gateway", action="append", default=[], help="trustless gateway fallback URL")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="import a file/directory and print its CID")
    a.add_argument("path")
    a.add_argument("--cid-version", type=int, default=0)
    a.add_argument("--only-hash", action="store_true")
    a.add_argument("-w", "--wrap", action="store_true")
    for name, hlp in (("cat", "print a file"), ("ls", "list a directory"), ("stat", "describe a path"),
                      ("resolve", "resolve a path to a CID")):
        sub.add_parser(name, help=hlp).add_argument("path")
    g = sub.add_parser("get", help="download to disk")
    g.add_argument("path")
    g.add_argument("-o", "--output", required=True)
    sub.add_parser("id", help="show node identity")
    s = sub.add_parser("serve", help="run a node and serve blocks until interrupted")
    s.add_argument("--listen", action="append", default=None)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    if args.cmd == "add" and args.only_hash:
        imp = Importer(MemoryBlockstore(), cid_version=args.cid_version)
        res = imp.add_path(args.path)
        print(imp.wrap([res]).cid if args.wrap else res.cid)
        return 0

    offline = args.cmd in ("add", "id") and not args.peer
    node = IPFSNode(args.repo, peers=args.peer, dht=not args.no_dht and not offline,
                    gateways=args.gateway, offline=offline,
                    listen=(args.listen or ["/ip4/0.0.0.0/tcp/4002"]) if args.cmd == "serve" else [])
    with node:
        if args.cmd == "add":
            print(node.add_path(args.path, wrap=args.wrap, cid_version=args.cid_version).cid)
        elif args.cmd == "cat":
            for chunk in node.cat_stream(args.path):
                sys.stdout.buffer.write(chunk)
        elif args.cmd == "ls":
            for e in node.ls(args.path):
                print(f"{e.cid}\t{e.size}\t{e.name}")
        elif args.cmd == "stat":
            for k, v in node.stat(args.path).items():
                print(f"{k}: {v}")
        elif args.cmd == "resolve":
            print(node.resolve(args.path))
        elif args.cmd == "get":
            node.get(args.path, args.output)
        elif args.cmd == "id":
            info = node.id()
            print(info["ID"])
            for addr in info["Addresses"]:
                print(" ", addr)
        elif args.cmd == "serve":
            for addr in node.id()["Addresses"]:
                print(addr)
            try:
                import threading
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. piped into `head`
        sys.stderr.close()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
