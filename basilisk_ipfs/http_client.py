"""HTTP clients: the Kubo RPC API and trustless (verifiable) HTTP gateways."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .cid import CID


class APIError(RuntimeError):
    pass


class KuboClient:
    """A thin client for a Kubo node's RPC API (default http://127.0.0.1:5001).

    Every RPC command is reachable via :meth:`call`; common ones have
    convenience wrappers.
    """

    def __init__(self, url="http://127.0.0.1:5001", timeout=120.0):
        self.base = url.rstrip("/") + "/api/v0/"
        self.timeout = timeout

    # ---- transport --------------------------------------------------------
    def _request(self, cmd, args=(), opts=None, files=None, stream=False):
        q = [("arg", str(a)) for a in (args if isinstance(args, (list, tuple)) else [args])]
        for k, v in (opts or {}).items():
            if v is None:
                continue
            if isinstance(v, bool):
                v = "true" if v else "false"
            q.append((k, str(v)))
        url = self.base + cmd + ("?" + urllib.parse.urlencode(q) if q else "")
        body, headers = None, {}
        if files is not None:
            body, ctype = _multipart(files)
            headers["Content-Type"] = ctype
        req = urllib.request.Request(url, data=body if body is not None else b"", method="POST",
                                     headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("Message", detail)
            except ValueError:
                pass
            raise APIError(f"{cmd}: {detail}") from None
        return resp if stream else resp.read()

    def call(self, cmd, *args, files=None, **opts):
        """Call any RPC command; JSON is decoded (NDJSON becomes a list)."""
        raw = self._request(cmd, args, _opts(opts), files)
        try:
            return json.loads(raw)
        except ValueError:
            lines = [l for l in raw.splitlines() if l.strip()]
            try:
                return [json.loads(l) for l in lines]
            except ValueError:
                return raw

    # ---- convenience --------------------------------------------------------
    def id(self):
        return self.call("id")

    def version(self):
        return self.call("version")

    def add_bytes(self, data: bytes, name="file", **opts) -> str:
        res = self.call("add", files=[("file", name, data)], **opts)
        res = res if isinstance(res, list) else [res]
        return res[-1]["Hash"]

    def add_path(self, path, include_hidden=False, **opts):
        """Add a file or directory tree (symlinks are stored as symlinks, hidden
        files skipped unless ``include_hidden``). Returns the added entries."""
        files = []
        root = os.path.abspath(path)
        base = os.path.dirname(root)

        def entry(full, rel):
            if os.path.islink(full):
                files.append(("file", rel, os.readlink(full).encode(), "application/symlink"))
            elif os.path.isdir(full):
                files.append(("file", rel, None, "application/x-directory"))
                for name in sorted(os.listdir(full)):
                    if include_hidden or not name.startswith("."):
                        entry(os.path.join(full, name), rel + "/" + name)
            else:
                with open(full, "rb") as f:
                    files.append(("file", rel, f.read(), "application/octet-stream"))

        entry(root, os.path.relpath(root, base))
        res = self.call("add", files=files, **opts)
        return res if isinstance(res, list) else [res]

    def cat(self, path, offset=None, length=None) -> bytes:
        return self._request("cat", [path], {"offset": offset, "length": length})

    def ls(self, path):
        return self.call("ls", path)["Objects"][0]["Links"]

    def block_get(self, cid) -> bytes:
        return self._request("block/get", [str(cid)])

    def block_put(self, data: bytes, cid_codec="raw", mhtype="sha2-256"):
        return self.call("block/put", files=[("data", "data", data)], cid_codec=cid_codec, mhtype=mhtype)

    def block_stat(self, cid):
        return self.call("block/stat", str(cid))

    def dag_get(self, path, output_codec="dag-json"):
        return self.call("dag/get", path, output_codec=output_codec)

    def dag_put(self, obj, store_codec="dag-cbor"):
        return self.call("dag/put", files=[("object data", "data", json.dumps(obj).encode())],
                         store_codec=store_codec, input_codec="dag-json")

    def pin_add(self, path, recursive=True):
        return self.call("pin/add", path, recursive=recursive)

    def pin_rm(self, path):
        return self.call("pin/rm", path)

    def pin_ls(self, type="recursive"):
        return self.call("pin/ls", type=type).get("Keys", {})

    def swarm_peers(self):
        return self.call("swarm/peers").get("Peers") or []

    def swarm_connect(self, addr):
        return self.call("swarm/connect", str(addr))

    def name_publish(self, path, key="self", lifetime="24h"):
        return self.call("name/publish", path, key=key, lifetime=lifetime)

    def name_resolve(self, name):
        return self.call("name/resolve", name)["Path"]

    def routing_findprovs(self, cid, num_providers=20):
        return self.call("routing/findprovs", str(cid), num_providers=num_providers)

    def resolve(self, path):
        return self.call("resolve", path)["Path"]


def _opts(opts):
    return {k.replace("_", "-"): v for k, v in opts.items()}


def _multipart(files):
    """``files``: (field, filename, data[, content_type]); data None = directory."""
    boundary = uuid.uuid4().hex
    out = bytearray()
    for item in files:
        field, name, data = item[:3]
        ctype = item[3] if len(item) > 3 else (
            "application/x-directory" if data is None else "application/octet-stream")
        quoted = urllib.parse.quote(name, safe="")
        out += (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field}"; filename="{quoted}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n").encode()
        out += data or b""
        out += b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


class GatewayClient:
    """Fetch blocks from a trustless HTTP gateway and verify them locally,
    so the gateway does not need to be trusted."""

    def __init__(self, url="http://127.0.0.1:8080", timeout=60.0):
        self.base = url.rstrip("/")
        self.timeout = timeout

    def get_block(self, cid) -> bytes:
        cid = CID.decode(cid)
        req = urllib.request.Request(f"{self.base}/ipfs/{cid}?format=raw",
                                     headers={"Accept": "application/vnd.ipld.raw"})
        try:
            data = urllib.request.urlopen(req, timeout=self.timeout).read()
        except urllib.error.HTTPError as e:
            raise KeyError(f"gateway returned {e.code} for {cid}") from None
        if not cid.verify(data):
            raise ValueError(f"gateway returned data not matching {cid}")
        return data

    get = get_block

    def get_ipns_record(self, name) -> bytes:
        req = urllib.request.Request(f"{self.base}/ipns/{name}?format=ipns-record",
                                     headers={"Accept": "application/vnd.ipfs.ipns-record"})
        return urllib.request.urlopen(req, timeout=self.timeout).read()
