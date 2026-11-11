# Open Domain Catalog (ODC) Chain Specification

**Version:** 0.1 (draft)
**Status:** Draft for review
**Editor:** Open Domain Catalog (ODC)

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

---

## 1. Overview

The ODC Chain is a distributed, publicly readable catalog of domain names organized by a Dewey Decimal-style classification. It is stored entirely as content-addressed blocks on IPFS and serves as an alternative to search engines: a reader navigates a hierarchy of categories (inodes) to reach a list of ranked domains (cards).

Properties:

- **Public read.** Anyone with access to an IPFS node can read the catalog.
- **Single writer.** Only the Open Domain Catalog publishes new blocks and defines the protocol.
- **Block storage on IPFS.** Every block is a pretty-printed (human-readable, indented) JSON document stored on IPFS. Its CID is its identity, and blocks link to each other by CID.
- **No token, fees, smart contracts, or throughput targets.** This is a catalog, not a transaction network.

## 2. Structure

The chain has two kinds of blocks:

1. **Inodes**: nine layers of category nodes. Each layer resolves one character of the call number.
2. **Cards**: a singly linked list of domain records attached to a call number of 1 to 9 characters.

A card chain may begin at any inode level, including the root. A category entry links to its subcategories with `next` and to its own card chain with `cards`, so a category can have both domains and inodes below it.

```
Root inode (layer 1)
  ├─ cards ─> Card ─ next ─> Card ─ next ─> null     (domains of a 1-character category)
  └─ next ──> Inode (layer 2)
               ├─ cards ─> Card ─ next ─> Card ─ next ─> null
               └─ next ──> Inode (layer 3)
                            └─ next ──> ... ─> Inode (layer 9)
                                                └─ cards ─> Card ─ next ─> Card ─ next ─> null
```

### 2.1 Call numbers

A call number is 9 characters, written in three groups of three separated by dots:

```
XXX.XXX.XXX
```

- Each character MUST be drawn from `0-9` and `A-Z`, uppercase only. This gives 36 possible values per position.
- The dots are separators, not call characters. A call is still 9 characters long.
- The dotted form `XXX.XXX.XXX` is the standard format. It is stored in blocks (the `call` fields in Section 4 and Section 5) for human readability, and clients, tools, and documentation MUST display call numbers in this form, grouping the characters in threes from the left. Clients SHOULD also accept the bare 9-character form as input.
- A *prefix* of length *n* (1 to 9) identifies a category at layer *n*. Prefixes use the same grouping, truncated: `A`, `AB`, `ABC`, `ABC.D`, `ABC.DE`, `ABC.DEF`, `ABC.DEF.G`, `ABC.DEF.GH`. A dot appears only after a completed group of three and is followed by at least one more character.

## 3. Storage and addressing

- All data MUST be stored as pretty-printed JSON. Every block MUST be a single JSON document.
- A block is stored on IPFS as bytes: the bytes of its pretty-printed JSON document. The CID of a block is derived from those bytes.
- Blocks are stored in IPFS. The codec, hash function, and CID format are left to IPFS.
- A link to another block is the CID of that block, written as a string. Because blocks are opaque bytes, IPFS does not follow these strings as links, so ODC must pin every block explicitly (Section 9).
- A link field with no target MUST be the JSON value `null`.

## 4. Inode block

An inode describes the children of one category prefix.

```json
{
  "type": "inode",
  "call": "AB",
  "0": {
    "desc": "Description of category AB0",
    "next": "<CID of inode for AB0>",
    "cards": "<CID of first card for AB0>"
  },
  "7": {
    "desc": "Description of category AB7",
    "next": "<CID of inode for AB7>",
    "cards": null
  }
}
```

| Field | Type | Rules |
|---|---|---|
| `type` | string | MUST be `"inode"`. |
| `call` | string | The prefix that leads *to* this inode, stored in the standard dotted form (Section 2.1). Its length, not counting dots, is 0 to 8, and the inode's layer is that length plus 1. For the root inode (layer 1) it is the empty string `""`. |
| `previous` | string or null | Root inode only; other inodes MUST NOT include it. The CID of the previously published root inode, or `null` for the first root. It records history and nothing more: the previous root is not needed by the current root, so it is not pinned and is not followed when reading (Section 9). |
| `links` | array | Root inode only; other inodes MUST NOT include it. The project links (Section 4.1). It is an empty array `[]` when there are none. |
| `0`-`9`, `A`-`Z` | object | Category entries, stored directly in the inode. Each key is a single call character, so none can collide with `type`, `call`, `previous`, or `links`, which are all longer. Any future inode field MUST also be longer than one character. Keys are sorted. Absent keys mean the category does not exist. |

Each category entry:

| Field | Type | Rules |
|---|---|---|
| `desc` | string | Human-readable description of the category. MUST be at most 128 characters. It is the empty string `""` if the category has no description. |
| `next` | string or null | The CID of the layer + 1 inode listing the subcategories of this category, or `null` if the category has no subcategories. Entries in a layer 9 inode MUST NOT include `next`, because there is no deeper layer. |
| `cards` | string or null | The CID of the **first card** of this category's own card chain, or `null` if the category has no domains of its own. |

**Card chains at any level.** A card chain may begin at any inode level, including the root, so a category of 1 to 9 characters may hold domains directly. `next` and `cards` are independent: a category may have both, either, or neither (subject to the rule below), so a category can have both domains and inodes below it. The domains in a category's `cards` chain belong to that category only. Domains of its subcategories are in the chains of those subcategories.

**Existence.** A category entry MUST exist if the category has a description, has domains of its own, or has any subcategory entries beneath it. A category that has none of these MUST NOT be present. A category with a description only exists with `next` and `cards` both `null` (at layer 9, with `cards` `null` and no `next`). A category with domains and no description exists with an empty `desc`.

Example: an entry at key `C` in a layer 3 inode whose `call` is `AB` describes category `ABC`. Its `next` is the layer 4 inode whose `call` is `ABC`. In turn, the entry at key `D` in that inode leads to the layer 5 inode whose `call` is `ABC.D`.

### 4.1 Project links

The root inode carries a `links` array of project links: URLs such as where to donate or where to read about the project. The links are data, not part of the protocol. Which links exist, how many there are, and what they say are decided by ODC and can change in any published root. Nothing about specific links is hardcoded in this specification or in clients.

```json
{
  "type": "inode",
  "call": "",
  "previous": "<CID of the previous root, or null>",
  "links": [
    {
      "label": "Donate",
      "url": "https://example.org/donate"
    },
    {
      "label": "About",
      "url": "https://example.org/about"
    }
  ],
  "A": {
    "desc": "Description of category A",
    "next": "<CID of inode for A>",
    "cards": null
  }
}
```

Each link:

| Field | Type | Rules |
|---|---|---|
| `label` | string | The text clients show for the link, for example "Donate" or "About". |
| `url` | string | The link target. |

- The order of the array is the order ODC wants links shown. Clients SHOULD preserve it.
- Labels are free text chosen by ODC. Clients MUST NOT depend on particular labels being present, and MUST NOT assume a fixed number of links.
- Because `links` is part of the root inode, changing a link changes the root CID. A new set of links reaches readers the same way any other edit does: it becomes visible when ODC publishes the new root (Section 7).

## 5. Card block

A card holds an ordered page of domains for one call number, which has 1 to 9 characters.

```json
{
  "type": "card",
  "index": 0,
  "call": "ABC.DEF.GHI",
  "domains": [
    {
      "rank": 9,
      "domain": "example.org",
      "desc": "Description of the site."
    },
    {
      "rank": 7,
      "domain": "example.net",
      "desc": "Description of the site."
    }
  ],
  "next": "<CID of the next card, or null>"
}
```

| Field | Type | Rules |
|---|---|---|
| `type` | string | MUST be `"card"`. |
| `index` | integer | The card's position in its call's card chain, starting at `0` for the first card (the one the category entry's `cards` field points to) and increasing by 1 with each `next`. |
| `call` | string | The call number of the category the chain belongs to, 1 to 9 characters (not counting dots), stored in the standard dotted form (Section 2.1). A chain that begins at a layer 9 inode has a full call such as `ABC.DEF.GHI`; one that begins at the layer 4 entry `D` of the inode whose `call` is `ABC` has the call `ABC.D`; one that begins at the root has a one-character call such as `A`. |
| `domains` | array | 1 to 25 domain records. |
| `next` | string or null | CID of the next card in the chain, or `null` for the last card. |

Domain record:

| Field | Type | Rules |
|---|---|---|
| `rank` | integer | 0 to 9. A mixture of cultural relevance and author authority (see below). |
| `domain` | string | At most 256 characters. MUST be stored fully lowercase and stripped of all leading and trailing protocol data: leading data such as a scheme (`https://`) or credentials (`user@`), and trailing data such as a port (`:8080`), path, query, fragment, or trailing slash. Only the domain name itself remains, for example `example.org` and not `https://example.org/index.html`. Subdomains are part of the domain and are not stripped, except for those on the blacklist (see below). |
| `desc` | string | At most 512 characters. |

**Scope.** The catalog only features publicly accessible domains. Non-DNS names (for example IPFS or other naming systems) MUST NOT be added. What counts as publicly accessible, and how it is judged, is left to ODC.

**Blacklist.** A `domain` MUST NOT begin with a blacklisted subdomain label. The blacklist initially contains `www` and its numbered variants (`www1`, `www2`, and so on), `ftp`, and `mail`. Other labels like these may be added to the blacklist at ODC's discretion. A site on a blacklisted label is cataloged under its domain without that label, so `www.example.org`, `ftp.example.org`, and `mail.example.org` are each cataloged as `example.org`. The blacklist applies only to subdomain labels, so a registered name that merely begins with the same letters (for example `wwwhatsnew.org`) is not affected.

**Rank.** Rank is a mixture of cultural relevance and author authority:

- `0`: neither culturally relevant, nor does the author carry authority on the topic.
- `4`: either fully culturally relevant, or the author has full authority on the topic.
- `9`: fully culturally relevant, and the author has full authority on the topic.

Judgement of how to rank a domain, including the values between these anchors, is left to ODC. Higher ranks sort first (Section 5.1).

### 5.1 Ordering within and across cards

- Domains across the whole card chain for one call MUST be sorted by `rank` **descending** (9 first, 0 last). Ties are broken by `domain` ascending (bytewise).
- Cards MUST be packed: every card except the last contains exactly 25 domains. This keeps the layout deterministic, so the same content always yields the same CIDs.
- A domain MUST belong to exactly one category. A `domain` value MUST appear at most once across the entire catalog, in a single card under a single call. Uniqueness is judged on the normalized form defined in Section 5 (lowercase, stripped of protocol data).
- Because this constraint spans the whole catalog, readers cannot verify it from one block. It is enforced by ODC at write time (Section 9), and a reader that detects the same domain under two calls SHOULD treat the catalog as malformed.

## 6. Size bounds

Worst case sizes, which fit comfortably within a single IPFS block:

- Inode: 36 entries x (128 character `desc` + 2 CIDs + overhead) is roughly 10 KB.
- Card: 25 domains x (256 + 512 characters + overhead) is roughly 25 KB.

Implementations MUST reject any block over 256 KiB.

## 7. Root and publication

The root is the layer 1 inode. Because every edit changes CIDs along the edited path up to the root, the root CID changes on every published update. A stable, mutable pointer is therefore needed:

- When to publish a new root CID is left solely to ODC's discretion. Publication is facilitated by a **SAVE** button (Section 9).
- ODC MUST publish the current root CID under an **IPNS name** controlled by the ODC key. IPNS is the current default mechanism. Other mechanisms may be added in a later revision of this specification.
- Clients resolve the IPNS name to obtain the current root CID, then traverse by CID.
- Integrity: every block's CID verifies its contents. Authenticity: the IPNS signature verifies that the root came from ODC.

## 8. Reading

**Lookup of a call `c1 c2 ... cn` (n from 1 to 9):**

1. Resolve the root CID and fetch the layer 1 inode.
2. For `i` from 1 to `n`: find the field named `ci` in the current inode. If absent, the category does not exist; stop. Otherwise read its `desc`. If `i < n`, fetch the inode at `next`; if `next` is `null`, the category has no subcategories, so the longer call does not exist; stop.
3. At `i = n`, the entry for the category is in hand. Its `cards` field leads to the category's own domains: if `null`, it has none; otherwise fetch the card and follow each card's `next` until `null`, and concatenate `domains` to get the ranked list. Its `next` field, absent at layer 9, leads to the inode listing its subcategories, if any.

**Browsing:** at any inode, the `desc` of each entry provides the category label, so a client can render the hierarchy without fetching children.

**Project links:** clients SHOULD show the project links (Section 4.1) from the root inode in their interface, in the order given, using each link's `label` as its text. Clients read the links from the current root each time they resolve it, rather than hardcoding them, so changes ODC publishes appear without a client update. If the root has no links, clients show none.

**Validation:** readers SHOULD verify that `call`, `type`, and (for cards) `index` are consistent with the position at which the block was reached, and MUST reject blocks that violate Sections 4 and 5.

## 9. Writing (ODC only)

ODC edits the catalog by adding, changing, or removing domains or categories. For each edit, ODC MUST:

1. Check, before adding a domain, that it does not begin with a blacklisted subdomain label (Section 5) and that it does not already exist elsewhere in the catalog (Section 5.1). To move a domain to a different category, remove it from its current call and add it to the new one as part of the same edit, so the catalog is never in a state where it appears twice.
2. Rebuild the affected card chain for the call, re-sorted and re-packed per Section 5.1.
3. Rebuild the inode (layer 1 to 9) whose entry's `cards` field points to that chain, updating `cards` with the new first-card CID, then rebuild each ancestor inode up to the root, updating `next` with each new child CID.
4. Add all new blocks to IPFS and **pin** them.

Unchanged subtrees are shared by CID and are not rewritten. ODC MUST unpin a block as soon as the current root no longer needs it. A block is needed while it is reachable from the published root (which readers are using) or from the newest root (which is awaiting publication). ODC does not retain old roots or their blocks as history: every block the current root does not need remains unpinned. The `previous` field of the root inode (Section 4) records the CID of the prior root, but that does not make the prior root needed.

The newest root inode produced by these edits is not visible to readers until it is published. Pressing the **SAVE** button publishes it, and that is the only thing SAVE does: it publishes the newest root inode (Section 7). How many edits accumulate between saves, and when a save happens, is solely ODC's decision.

### 9.1 Editing project links

ODC admin tools SHOULD provide a way to add, change, reorder, and remove project links (Section 4.1) on the fly, without editing blocks by hand and without any change to client software. A link edit rebuilds only the root inode (and nothing beneath it), pins the new root, and, like every other edit, becomes visible to readers when ODC presses **SAVE**.

## 10. Availability, governance, and trust

- **Availability:** ODC MUST pin all blocks reachable from the current root. Third parties MAY pin any part of the catalog, and doing so is encouraged.
- **Governance:** ODC alone defines and changes the protocol.
- **No consensus mechanism:** There are no competing writers, so there are no forks, validators, or fees. Trust in content derives from trust in ODC's key.
