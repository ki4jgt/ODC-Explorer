"""Reader for the Open Domain Catalog chain (odc-chain-spec.md v0.1).

Everything here is read-only. Blocks are fetched through a ``fetch(cid) -> bytes``
callable (normally an ``IPFSNode``), validated against Sections 4 and 5 of the
spec. Blocks live in basilisk-ipfs' blockstore, whose garbage collector decides what
stays on disk. On top of that, a small in-memory cache (``BlockCache``) keeps
recently read blocks, parsed, keyed by CID. It isn't tied to a catalog root:
blocks unchanged between roots keep their CIDs, so they stay cached across
publications.

Reading order starts at an *origin* category and moves forward along the
shelves until the end of the catalog:

1. the origin's own domains, then its subcategories (depth first, key order),
   until they are exhausted;
2. then the origin's next sibling with its subcategories, and the siblings after
   that;
3. when a level runs out of siblings, the parent's next sibling, and so on up.

It never goes back to categories before the origin: reading stops at the last
category of the catalog. This is call-number order starting from the origin; from
the root (origin ``""``) it is the whole catalog. Paging is a cursor
``(call, offset)``, so a page of 25 runs on into the following categories when
the current one has fewer domains.
"""

import json
import re
import threading
from collections import OrderedDict

PAGE_SIZE = 25
MAX_BLOCK = 256 * 1024
_KEY_RE = re.compile(r"^[0-9A-Z]$")
_CALL_RE = re.compile(r"^[0-9A-Z]{0,9}$")


class MalformedBlock(Exception):
    """A block violates the spec and must be rejected (Section 8)."""


class NotFound(LookupError):
    """The requested call number does not exist in the catalog."""


class Hidden(Exception):
    """The requested category is inside a branch the reader chose to hide."""


def is_hidden(bare, hide):
    """True if call ``bare`` is one of the ``hide`` prefixes or below one."""
    return any(p and bare.startswith(p) for p in hide)


# ---- call numbers (Section 2.1) ---------------------------------------------

def parse_call(text):
    """Accept dotted or bare input (any case) and return the bare form, or None."""
    bare = (text or "").strip().replace(".", "").replace(" ", "").upper()
    return bare if _CALL_RE.match(bare) else None


def fmt_call(bare):
    """Bare ``ABCDEFG`` -> standard dotted ``ABC.DEF.G``."""
    return ".".join(bare[i:i + 3] for i in range(0, len(bare), 3))


# ---- validation ---------------------------------------------------------------

def _is_link(v):
    return v is None or (isinstance(v, str) and v != "")


def validate_links(links):
    """Project links (Section 4.1): an array of {label, url} strings."""
    if not isinstance(links, list):
        raise MalformedBlock("links must be an array")
    for link in links:
        if not (isinstance(link, dict) and isinstance(link.get("label"), str)
                and isinstance(link.get("url"), str)):
            raise MalformedBlock("each link needs a string label and url")


ROOT_ONLY = ("previous", "links")


def validate_inode(block, bare_call):
    layer = len(bare_call) + 1
    if block.get("type") != "inode":
        raise MalformedBlock("expected an inode")
    if block.get("call") != fmt_call(bare_call):
        raise MalformedBlock(f"inode call {block.get('call')!r} != {fmt_call(bare_call)!r}")
    if layer == 1:
        if "previous" in block and not _is_link(block["previous"]):
            raise MalformedBlock("bad previous link")
        if "links" in block:            # roots published before links existed have none
            validate_links(block["links"])
    else:
        for field in ROOT_ONLY:
            if field in block:
                raise MalformedBlock(f"only the root inode may carry {field}")
    for key, entry in block.items():
        if len(key) > 1:
            continue                    # type, call, root fields, or a future field (Section 4)
        if not _KEY_RE.match(key):
            raise MalformedBlock(f"bad inode key {key!r}")
        if not isinstance(entry, dict):
            raise MalformedBlock(f"entry {key} is not an object")
        desc = entry.get("desc")
        if not isinstance(desc, str) or len(desc) > 128:
            raise MalformedBlock(f"entry {key}: bad desc")
        if not _is_link(entry.get("cards", "missing")):
            raise MalformedBlock(f"entry {key}: bad cards link")
        if layer == 9:
            if "next" in entry:
                raise MalformedBlock(f"entry {key}: layer 9 entries have no next")
        elif not _is_link(entry.get("next", "missing")):
            raise MalformedBlock(f"entry {key}: bad next link")
        if not desc and entry.get("cards") is None and entry.get("next") is None:
            raise MalformedBlock(f"entry {key}: empty category must not exist")


def validate_card(block, bare_call, index):
    if block.get("type") != "card":
        raise MalformedBlock("expected a card")
    if block.get("call") != fmt_call(bare_call):
        raise MalformedBlock(f"card call {block.get('call')!r} != {fmt_call(bare_call)!r}")
    if block.get("index") != index:
        raise MalformedBlock(f"card index {block.get('index')!r} != {index}")
    doms = block.get("domains")
    if not isinstance(doms, list) or not 1 <= len(doms) <= PAGE_SIZE:
        raise MalformedBlock("card must hold 1 to 25 domains")
    if not _is_link(block.get("next", "missing")):
        raise MalformedBlock("bad card next link")
    if block["next"] is not None and len(doms) != PAGE_SIZE:
        raise MalformedBlock("cards before the last must hold exactly 25 domains")
    for d in doms:
        rank = d.get("rank") if isinstance(d, dict) else None
        if not isinstance(rank, int) or isinstance(rank, bool) or not 0 <= rank <= 9:
            raise MalformedBlock("bad domain rank")
        name = d.get("domain")
        if not isinstance(name, str) or not name or len(name) > 256 or name != name.lower():
            raise MalformedBlock("bad domain name")
        if not isinstance(d.get("desc"), str) or len(d["desc"]) > 512:
            raise MalformedBlock("bad domain desc")


def _sort_key(d):
    return (-d["rank"], d["domain"].encode())


# ---- the reader ---------------------------------------------------------------

class BlockCache:
    """Size-capped LRU cache of parsed blocks, keyed by CID.

    Blocks are immutable, so an entry never goes stale; it is only dropped
    when the cache needs room. The cap counts each block's raw size.
    """

    def __init__(self, max_bytes=64 * 1024 * 1024):
        self.max_bytes = max_bytes
        self._items = OrderedDict()   # cid -> (parsed block, raw size)
        self._bytes = 0
        self._lock = threading.Lock()
        self.hits = self.misses = self.evictions = 0

    def get(self, cid):
        with self._lock:
            item = self._items.get(cid)
            if item is None:
                self.misses += 1
                return None
            self._items.move_to_end(cid)
            self.hits += 1
            return item[0]

    def put(self, cid, block, size):
        if size > self.max_bytes:
            return
        with self._lock:
            old = self._items.pop(cid, None)
            if old is not None:
                self._bytes -= old[1]
            self._items[cid] = (block, size)
            self._bytes += size
            while self._bytes > self.max_bytes:
                _, (_, s) = self._items.popitem(last=False)
                self._bytes -= s
                self.evictions += 1

    def stats(self):
        with self._lock:
            return {"blocks": len(self._items), "bytes": self._bytes, "max_bytes": self.max_bytes,
                    "hits": self.hits, "misses": self.misses, "evictions": self.evictions}


class Catalog:
    """Validated, lazily fetched view of one root inode. Reads go to ``cache``
    (shared across roots) and then to ``fetch`` (basilisk-ipfs' blockstore, then the
    network)."""

    def __init__(self, fetch, root_cid, cache=None):
        self._fetch = fetch
        self.root = root_cid
        self._cache = cache

    def _get(self, cid, validator, *args):
        block = self._cache.get(cid) if self._cache is not None else None
        if block is None:
            raw = self._fetch(cid)
            if len(raw) > MAX_BLOCK:
                raise MalformedBlock(f"block {cid} is over 256 KiB")
            try:
                block = json.loads(raw)
            except ValueError as e:
                raise MalformedBlock(f"block {cid} is not JSON: {e}") from None
            if not isinstance(block, dict):
                raise MalformedBlock(f"block {cid} is not a JSON object")
            if self._cache is not None:
                self._cache.put(cid, block, len(raw))
        # Validation depends on where the block was reached, so run it every time.
        validator(block, *args)
        return block

    def inode(self, cid, bare_call):
        return self._get(cid, validate_inode, bare_call)

    def card(self, cid, bare_call, index):
        return self._get(cid, validate_card, bare_call, index)

    @staticmethod
    def keys(inode):
        """Category keys in call order (0-9, then A-Z, which is also ASCII order)."""
        return sorted(k for k in inode if _KEY_RE.match(k))

    def links(self):
        """The root's project links in ODC's order (Section 4.1); [] if none."""
        return [{"label": l["label"], "url": l["url"]}
                for l in self.inode(self.root, "").get("links", [])]

    # -- lookup (Section 8) --
    def path(self, bare):
        """Inodes and entries along ``bare``: [(inode, key)], one per character."""
        inode = self.inode(self.root, "")
        out = []
        for i, ch in enumerate(bare):
            if ch not in inode:
                raise NotFound(fmt_call(bare[:i + 1]))
            out.append((inode, ch))
            if i < len(bare) - 1:
                nxt = inode[ch].get("next")
                if not nxt:
                    raise NotFound(fmt_call(bare[:i + 2]))
                inode = self.inode(nxt, bare[:i + 1])
        return out

    def category(self, bare, hide=()):
        """Description of a category and its children, for browsing. Children
        inside a ``hide`` branch are left out; a hidden category raises Hidden."""
        if is_hidden(bare, hide):
            raise Hidden(fmt_call(bare))
        steps = self.path(bare)
        crumbs = [{"call": fmt_call(bare[:i + 1]), "desc": inode[k]["desc"]}
                  for i, (inode, k) in enumerate(steps)]
        if bare:
            entry = steps[-1][0][steps[-1][1]]
            child_cid = entry.get("next")
        else:
            entry, child_cid = None, self.root
        children = []
        if child_cid:
            child = self.inode(child_cid, bare)
            for k in self.keys(child):
                if is_hidden(bare + k, hide):
                    continue
                e = child[k]
                children.append({"call": fmt_call(bare + k), "desc": e["desc"],
                                 "has_children": bool(e.get("next")),
                                 "has_domains": bool(e.get("cards"))})
        return {"call": fmt_call(bare), "desc": entry["desc"] if entry else "",
                "has_domains": bool(entry and entry.get("cards")),
                "breadcrumbs": crumbs, "children": children}

    def domains(self, bare, cards_cid, start=0):
        """Yield (offset, domain) from a category's card chain, checking order."""
        index, prev, cid = 0, None, cards_cid
        while cid:
            card = self.card(cid, bare, index)
            base = index * PAGE_SIZE
            for i, d in enumerate(card["domains"]):
                k = _sort_key(d)
                if prev is not None and k <= prev:
                    raise MalformedBlock(f"card chain for {fmt_call(bare)} is out of order")
                prev = k
                if base + i >= start:
                    yield base + i, d
            index, cid = index + 1, card["next"]

    # -- reading order --
    def _subtree(self, inode, key, prefix, crumbs, warnings, hide=()):
        """Pre-order walk: the category itself, then each subcategory's subtree.
        Hidden branches are skipped without fetching any of their blocks."""
        if is_hidden(prefix + key, hide):
            return
        entry, call = inode[key], prefix + key
        crumbs = crumbs + [entry["desc"]]
        yield call, entry, crumbs
        nxt = entry.get("next")
        if not nxt:
            return
        try:
            child = self.inode(nxt, call)
        except (MalformedBlock, LookupError, OSError) as e:
            warnings.append(f"{fmt_call(call)}: {e}")
            return
        for k in self.keys(child):
            yield from self._subtree(child, k, call, crumbs, warnings, hide)

    def categories(self, origin, warnings, hide=()):
        """Yield (bare call, entry, crumbs) for the origin and every category
        after it, in reading order, ending at the last category of the catalog."""
        root = self.inode(self.root, "")
        if not origin:
            for k in self.keys(root):
                yield from self._subtree(root, k, "", [], warnings, hide)
            return
        steps = self.path(origin)
        descs = [inode[k]["desc"] for inode, k in steps]
        inode, key = steps[-1]
        yield from self._subtree(inode, key, origin[:-1], descs[:-1], warnings, hide)
        for level in range(len(origin) - 1, -1, -1):
            inode, key = steps[level]
            keys = self.keys(inode)
            i = keys.index(key)
            for k in keys[i + 1:]:          # later siblings only; never wrap back
                yield from self._subtree(inode, k, origin[:level], descs[:level], warnings, hide)

    def stream(self, origin, call=None, offset=0, warnings=None, hide=()):
        """Yield every domain in reading order from ``origin``, resuming at
        ``(call, offset)`` within that order (default: the start of ``origin``).

        Categories before the cursor are passed over without reading their
        cards. A malformed subtree is skipped and noted in ``warnings``.
        """
        warnings = warnings if warnings is not None else []
        target = origin if call is None else call
        if is_hidden(origin, hide) or is_hidden(target, hide):
            raise Hidden(fmt_call(target))
        if target:
            self.path(target)                 # NotFound for a cursor that doesn't exist
        started = not target
        for bare, entry, crumbs in self.categories(origin, warnings, hide):
            start = 0
            if not started:
                if bare != target:
                    continue
                started, start = True, offset
            if not entry.get("cards"):
                continue
            try:
                for off, d in self.domains(bare, entry["cards"], start):
                    yield {"call": fmt_call(bare), "offset": off, "crumbs": crumbs,
                           "rank": d["rank"], "domain": d["domain"], "desc": d["desc"]}
            except (MalformedBlock, LookupError, OSError) as e:
                warnings.append(f"{fmt_call(bare)}: {e}")

    def page(self, origin, call=None, offset=0, size=PAGE_SIZE, hide=()):
        """One page of the stream plus the cursor for the page after it."""
        warnings, items, nxt = [], [], None
        for item in self.stream(origin, call, offset, warnings, hide):
            if len(items) == size:
                nxt = {"call": item["call"], "offset": item["offset"]}
                break
            items.append(item)
        return {"items": items, "next": nxt, "warnings": warnings}
