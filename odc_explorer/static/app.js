/* ODC chain explorer: a hash-routed single page.
 *   #/                         home: call-number box and the top-level "drawers"
 *   #/c/<call>/<offset>?...    browse: 25 domains in reading order from a cursor
 *   #/ipfs                     status of the embedded IPFS node
 * Everything is served by the local Flask app; the page makes no third-party
 * requests. Project links (Donate, About, ...) come from the catalog's root
 * inode (spec Section 4.1) and are only followed when clicked.
 */
(() => {
  "use strict";

  // ---------- settings you may want to change ----------
  const DONATE_EVERY_MONTHS = 3;                     // ask again 3 months after an answer
  const DONATE_LABEL = "donate";                     // the banner uses the project link with this label
  const ADULT_CALL = "0";                            // branch hidden by the 18+ switch
  const PAGE = 25;

  // ---------- helpers ----------
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const view = $("#view");
  const topbar = $("#topbar");

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const bare = (call) => String(call || "").replace(/\./g, "").toUpperCase();
  const dotted = (b) => (bare(b).match(/.{1,3}/g) || []).join(".");
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  const store = {   // localStorage can be unavailable (private mode, blocked)
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  };

  async function api(path, params = {}) {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null));
    const r = await fetch(`/api/${path}?${qs}`);
    const body = await r.json().catch(() => ({ message: r.statusText }));
    if (!r.ok) throw Object.assign(new Error(body.message || r.statusText), { status: r.status, kind: body.error });
    return body;
  }

  // ---------- links and routing ----------
  const browseHref = (call, offset = 0, extra = {}) => {
    const qs = new URLSearchParams(Object.entries(extra).filter(([, v]) => v != null && v !== "")).toString();
    return `#/c/${encodeURIComponent(dotted(call)) || "-"}/${offset}${qs ? "?" + qs : ""}`;
  };
  const shelfHref = (call) => browseHref(call, 0, { from: dotted(call) });

  function parseHash() {
    const [path, query = ""] = (location.hash.replace(/^#/, "") || "/").split("?");
    return { parts: path.split("/").filter(Boolean).map(decodeURIComponent), q: new URLSearchParams(query) };
  }

  // Same page = same path and same non-empty parameters, in any order
  // (``#/c/-/0`` and ``#/c/-/0?from=`` are one page).
  const canonical = (h) => {
    const [path, query = ""] = String(h).replace(/^#/, "").split("?");
    const params = [...new URLSearchParams(query)].filter(([, v]) => v !== "").sort();
    return path.replace(/\/+$/, "") + "?" + new URLSearchParams(params);
  };
  const isCurrentPage = (h) => canonical(h) === canonical(location.hash || "#/");

  // Pages only change when the reader acts. Every navigation reads the latest
  // catalog; a link to the current page is redrawn explicitly, since the URL
  // (and so ``hashchange``) wouldn't change.
  let renderToken = 0;
  async function route() {
    const token = ++renderToken;
    const stale = () => token !== renderToken;
    const { parts, q } = parseHash();
    window.scrollTo({ top: 0 });
    stopIpfsRefresh();
    if (parts[0] === "ipfs") return renderIpfs(stale);
    if (parts[0] === "c") {
      const call = parts[1] && parts[1] !== "-" ? parts[1] : "";
      return renderBrowse(call, Math.max(0, parseInt(parts[2] || "0", 10) || 0), q, stale);
    }
    return renderHome(stale);
  }

  // ---------- theme and the 18+ switch ----------
  const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; };
  applyTheme(store.get("odc-theme"));
  function toggleTheme() {
    const t = document.documentElement.dataset.theme;
    const dark = t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(dark ? "light" : "dark");
    store.set("odc-theme", dark ? "light" : "dark");
  }

  let hideAdult = store.get("odc-hide-adult") === "1";
  const hideParam = () => (hideAdult ? ADULT_CALL : undefined);
  const adultToggle = () => `<button type="button" class="adult-toggle" data-adult-toggle aria-pressed="${hideAdult}"
      title="${hideAdult ? `Adult content (call ${ADULT_CALL}) is hidden. Click to show it.` : `Hide adult content (call ${ADULT_CALL} and everything under it)`}">
      <span class="sw" aria-hidden="true"></span>18+<span class="lbl"> ${hideAdult ? "hidden" : "shown"}</span></button>`;
  const syncAdultToggles = () => $$("[data-adult-slot]").forEach((el) => (el.innerHTML = adultToggle()));
  function toggleAdult() {
    hideAdult = !hideAdult;
    store.set("odc-hide-adult", hideAdult ? "1" : "0");
    syncAdultToggles();
    route();
  }

  // ---------- events (one delegated handler per kind) ----------
  document.addEventListener("click", (e) => {
    const t = e.target;
    if (t.closest("#theme")) return toggleTheme();
    if (t.closest("[data-adult-toggle]")) return toggleAdult();
    const donate = t.closest("[data-donate]");
    if (donate) return answerDonate(donate.dataset.donate);
    const copy = t.closest("[data-copy]");
    if (copy) return copyText(copy);
    const a = t.closest('a[href^="#"]');
    if (a && !e.defaultPrevented && e.button === 0 && !(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey)
        && isCurrentPage(a.getAttribute("href"))) {
      e.preventDefault();
      route();
    }
  });

  // The call-number box (spec Section 8 lookup; there is no text search).
  document.addEventListener("submit", (e) => {
    const form = e.target.closest("[data-search]");
    if (!form) return;
    e.preventDefault();
    const input = form.q;
    const b = bare(input.value.trim().replace(/^(#|call:)/i, "").replace(/\s+/g, ""));
    if (!b) { location.hash = "#/"; return; }
    if (!/^[0-9A-Z]{1,9}$/.test(b)) {
      input.setCustomValidity("Call numbers are 1–9 characters of 0-9 and A-Z, e.g. 05 or ABC.DEF.G");
      input.reportValidity();
      input.addEventListener("input", () => input.setCustomValidity(""), { once: true });
      return;
    }
    input.blur();
    const target = shelfHref(b);
    if (isCurrentPage(target)) route(); else location.hash = target;
  });

  document.addEventListener("keydown", (e) => {
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) return;
    if (e.key === "/") {
      $$(".search input").find((i) => i.offsetParent)?.focus();
      e.preventDefault();
    } else if (!e.metaKey && !e.ctrlKey && !e.altKey) {
      if (e.key === "ArrowRight") $("[data-next]:not([disabled])")?.click();
      if (e.key === "ArrowLeft") $("[data-prev]:not([disabled])")?.click();
    }
  });
  window.addEventListener("hashchange", () => route());

  const setQuery = (q) => $$(".search input").forEach((i) => (i.value = q));

  // ---------- shared pieces ----------
  const tileColors = ["#8a2d1f", "#3b5b4a", "#a8822f", "#2f4a7a", "#6b3a5b", "#7a5230", "#40606b", "#5a5f2a"];
  function tile(domain) {
    let h = 0;
    for (const ch of domain) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return `<div class="mono-tile" style="background:${tileColors[h % tileColors.length]}" aria-hidden="true">${esc(domain[0] || "?")}</div>`;
  }
  const rank = (r) => `<span class="rank" title="Rank ${r} of 9 — cultural relevance and author authority">${
    Array.from({ length: 9 }, (_, i) => `<i class="${i < r ? "on" : ""}"></i>`).join("")}<b>${r}</b></span>`;
  function crumbLinks(call, descs) {
    const b = bare(call);
    return descs.map((d, i) => `<a href="${shelfHref(b.slice(0, i + 1))}">${esc(d || dotted(b.slice(0, i + 1)))}</a>`)
      .join(`<span class="sep">›</span>`);
  }
  const resultItem = (it, n) => `<li class="result" style="animation-delay:${Math.min(n, 12) * 18}ms">
      ${tile(it.domain)}
      <div>
        <div class="url"><span>https://${esc(it.domain)}</span>${rank(it.rank)}</div>
        <h2><a href="https://${esc(it.domain)}" target="_blank" rel="noopener noreferrer">${esc(it.domain)}</a></h2>
        <p>${esc(it.desc) || "<em>No description.</em>"}</p>
      </div>
    </li>`;
  const skeleton = (note) => (note ? `<p class="loading-note">${esc(note)}</p>` : "") +
    `<div class="skel-item"><div class="skel w30"></div><div class="skel w55 tall"></div><div class="skel w85"></div></div>`.repeat(5);
  const backLink = `<a class="btn" href="#/">Back to the catalog</a>`;
  const errorBox = (e) => {
    if (e.kind === "hidden") {
      return `<div class="empty"><h3>Adult content is hidden</h3>This category is under call number ${esc(ADULT_CALL)}, which you've chosen to hide.
        <div class="box-actions">${backLink}<button class="btn" type="button" data-adult-toggle>Show adult content</button></div></div>`;
    }
    const title = e.status === 404 ? "Not in the catalog" : e.status === 400 ? "Not a call number" : "Couldn't read the chain";
    return `<div class="error"><strong>${title}</strong><br>${esc(e.message)}<div class="box-actions">${backLink}</div></div>`;
  };

  // ---------- home ----------
  async function renderHome(stale) {
    topbar.hidden = true;
    document.title = "Open Domain Catalog";
    view.innerHTML = `<section class="home">
      <a class="wordmark big" href="#/"><span class="mark" aria-hidden="true"><i></i><i></i><i></i></span><span>Open Domain <em>Catalog</em></span></a>
      <p class="tagline">A library of the web, shelved by call number and read straight from IPFS.</p>
      <form class="search" data-search>
        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        <input name="q" type="search" placeholder="Go to a call number, e.g. 05 or ABC.DEF.G" autocomplete="off" aria-label="Go to call number" autofocus>
        <kbd>/</kbd>
      </form>
      <div class="actions">
        <a class="btn primary" href="${browseHref("")}">Browse the stacks from the start →</a>
        <a class="btn" href="#/ipfs"><span class="dot" data-reach></span>IPFS node status</a>
        <span data-adult-slot>${adultToggle()}</span>
      </div>
      <h2 class="section-title">The card catalog</h2>
      <div class="drawers" id="drawers">${`<div class="drawer"><div class="skel w30"></div><div class="skel w70 tall"></div></div>`.repeat(3)}</div>
    </section>`;
    refreshReachDot();
    try {
      const data = await api("category", { call: "", hide: hideParam() });
      noteRoot(data.root, data.links);
      if (stale()) return;
      const what = (c) => [c.has_children && "Subcategories", c.has_domains && "Domains"].filter(Boolean).join(" · ") || "Empty shelf";
      $("#drawers").innerHTML = data.children.map((c) => `
        <a class="drawer" href="${shelfHref(c.call)}">
          <span class="pull" aria-hidden="true"></span>
          <span class="label">${esc(c.call)}</span>
          <h3>${esc(c.desc || "Untitled")}</h3>
          <p>${what(c)}</p>
        </a>`).join("") || `<div class="empty">The catalog has no categories yet.</div>`;
    } catch (e) {
      if (!stale()) $("#drawers").outerHTML = errorBox(e);
    }
  }

  // ---------- browse ----------
  // Category details only change with the catalog root, so cache them per
  // 18+ setting and start over whenever the server reports a new root.
  const catCache = new Map();
  let cacheRoot = null;
  function noteRoot(root, links) {
    if (root && root !== cacheRoot) {
      if (cacheRoot !== null) catCache.clear();
      cacheRoot = root;
    }
    if (links) setProjectLinks(links);
  }
  function getCategory(b) {
    const key = `${hideAdult ? "h" : "a"}|${b}`;
    if (!catCache.has(key)) {
      const p = api("category", { call: b, hide: hideParam() }).then((c) => {
        if (c.root !== cacheRoot) { noteRoot(c.root, c.links); catCache.set(key, p); }   // newer catalog
        return c;
      }).catch((e) => { catCache.delete(key); throw e; });
      catCache.set(key, p);
    }
    return catCache.get(key);
  }

  // Sidebar: the breadcrumb to the current category, then the shelf it sits on
  // (its siblings, with it highlighted and its own subcategories nested).
  // ``parent`` is null at "All shelves".
  function rail(cur, parent) {
    const link = (c, cls = "") => `<li><a class="${cls}" href="${shelfHref(c.call)}"><span class="c">${esc(c.call)}</span>${esc(c.desc || "Untitled")}</a></li>`;
    const crumbs = cur.breadcrumbs;
    const loc = `<li><a href="${browseHref("")}" class="${crumbs.length ? "" : "here"}"><span class="c">—</span>All shelves</a></li>` +
      crumbs.map((c, i) => link(c, i === crumbs.length - 1 ? "here" : "")).join("");
    const shelf = parent ? parent.children : cur.children;
    const title = parent?.call ? `${esc(parent.call)} ${esc(parent.desc || "Untitled")}` : "Top shelves";
    const items = shelf.map((c) => (parent && c.call === cur.call)
      ? link(c, "depth-1 here") + cur.children.map((k) => link(k, "depth-2")).join("")
      : link(c, "depth-1")).join("");
    return `<h4>Location</h4><ul class="tree">${loc}</ul>
      <h4>${title}</h4><ul class="tree">${items || `<li><span class="tree muted">No categories here.</span></li>`}</ul>
      <div class="rail-links" id="rail-links">${railLinks()}</div>`;
  }

  async function drawRail(b, stale) {
    try {
      const [cur, parent] = await Promise.all([getCategory(b), b ? getCategory(b.slice(0, -1)) : null]);
      if (stale() || !$("#rail")) return null;
      $("#rail").innerHTML = rail(cur, parent);
      return cur;
    } catch { return null; }
  }

  // Header card for the subject the page is on (the same category as the
  // sidebar). ``start`` is where reading began, noted when different.
  function headCard(cur, start) {
    const crumbs = cur.breadcrumbs.length > 1
      ? crumbLinks(cur.call, cur.breadcrumbs.slice(0, -1).map((b) => b.desc))
      : "Open Domain Catalog";
    const began = bare(start.call) !== bare(cur.call)
      ? ` · started at <a href="${shelfHref(start.call)}">${esc(start.call ? `${start.call} ${start.desc || "Untitled"}` : "All shelves")}</a>`
      : "";
    return `<div class="catcard">
      <div class="top"><span class="call">${esc(cur.call || "000.000.000")}</span><span class="crumbs">${crumbs}</span></div>
      <h1>${esc(cur.call ? cur.desc || "Untitled category" : "All shelves")}</h1>
      <div class="meta">${plural(cur.children.length, "subcategory", "subcategories")} ·
        ${cur.has_domains ? "holds domains of its own" : "no domains of its own"}${began}</div>
    </div>`;
  }

  // Next pushes onto this trail so Previous can go back through history; a
  // deep link with no trail falls back to the start of the shelf.
  const trail = [];

  async function renderBrowse(call, offset, q, stale) {
    topbar.hidden = false;
    setQuery("");
    const from = q.has("from") ? q.get("from") : dotted(call);
    const fromB = bare(from);
    const pageNo = Math.max(1, parseInt(q.get("p") || "1", 10) || 1);
    view.innerHTML = `<div class="layout"><aside class="rail" id="rail">${skeleton()}</aside>
      <section><div id="head"><div class="catcard"><div class="skel w20"></div><div class="skel w50 taller"></div></div></div>
      <div id="flow">${skeleton("Fetching blocks over IPFS — the first visit to a shelf can take a moment.")}</div></section></div>`;

    let start, flow;
    try {
      [start, flow] = await Promise.all([
        api("category", { call: fromB, hide: hideParam() }).then((c) => { noteRoot(c.root, c.links); return c; }),
        api("flow", { from: fromB, call: bare(call), offset, hide: hideParam() })
          .then((f) => { noteRoot(f.root, f.links); if (!stale()) drawFlow(f); return f; }),
      ]);
    } catch (e) {
      if (!stale()) view.innerHTML = `<div class="layout single"><section>${errorBox(e)}</section></div>`;
      return;
    }
    if (stale()) return;
    // Sidebar and header follow the subject of the page: the category of its
    // first domain (an empty page, at the end of the catalog, shows the start).
    const cur = (await drawRail(flow.items.length ? bare(flow.items[0].call) : fromB, stale)) || start;
    if (stale()) return;
    $("#head").innerHTML = headCard(cur, start);
    document.title = `${cur.call ? `${cur.call} ${cur.desc || ""}` : "All shelves"} · Open Domain Catalog`;

    function shelfTag(b) {
      if (!fromB || b === fromB) return "";
      if (b.startsWith(fromB)) return "Subcategory";
      if (b.startsWith(fromB.slice(0, -1)) && b.length >= fromB.length) return "Sibling";
      return "Next on the shelf";
    }

    function drawFlow(f) {
      let html = f.warnings?.length
        ? `<div class="notice"><strong>Skipped malformed blocks:</strong> ${f.warnings.map(esc).join("; ")}</div>` : "";
      if (!f.items.length) {
        html += `<div class="empty"><h3>End of the catalog</h3>
          ${offset || pageNo > 1 ? "There are no more domains after this point in the catalog."
                                 : "This category, its subcategories and everything after it in the catalog have no domains."}
          <div class="box-actions"><a class="btn" href="${browseHref("")}">Start again from the first shelf</a></div></div>`;
      } else {
        let last = null;
        html += `<ol class="results">` + f.items.map((it, n) => {
          let mark = "";
          if (it.call !== last) {
            const b = bare(it.call), tag = shelfTag(b), href = browseHref(b, 0, { from: it.call });
            const cont = n === 0 && it.offset > 0 ? " <small>(continued)</small>" : "";
            const within = it.crumbs.length > 1 ? `<small> in ${esc(it.crumbs.slice(0, -1).join(" › "))}</small>` : "";
            mark = `<li class="shelf-mark" data-call="${esc(b)}">
              <a class="spine" href="${href}">${esc(it.call)}</a>
              <a class="where" href="${href}">${esc(it.crumbs[it.crumbs.length - 1] || "Untitled")}${cont}${within}</a>
              ${tag ? `<span class="flowtag">${tag}</span>` : ""}
            </li>`;
            last = it.call;
          }
          return mark + resultItem(it, n);
        }).join("") + `</ol>`;
        if (!f.next) html += `<p class="end-note">End of the catalog</p>`;
      }
      const first = (pageNo - 1) * PAGE + 1, shown = f.items.length;
      html += `<nav class="pager" aria-label="Pages">
        <button class="btn" data-prev ${pageNo > 1 || offset > 0 || bare(call) !== fromB ? "" : "disabled"}>← Previous ${PAGE}</button>
        <span class="pos">${shown ? `Domains ${first}–${first + shown - 1} from <code>${esc(from || "the first shelf")}</code> onward` : ""}</span>
        <button class="btn primary" data-next ${f.next ? "" : "disabled"}>Next ${PAGE} →</button>
      </nav>`;
      $("#flow").innerHTML = html;
      $("[data-next]").addEventListener("click", () => {
        if (!f.next) return;
        trail.push(location.hash);
        location.hash = browseHref(f.next.call, f.next.offset, { from, p: pageNo + 1 });
      });
      $("[data-prev]").addEventListener("click", () => {
        if (trail.length) { trail.pop(); history.back(); } else location.hash = browseHref(from, 0, { from });
      });
    }
  }

  // ---------- IPFS status page (refreshes itself every 5 s while open) ----------
  const fmtBytes = (n) => {
    if (n == null || isNaN(n)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    for (n = Number(n); n >= 1000 && i < u.length - 1; i++) n /= 1000;
    return `${n.toFixed(n < 10 && i ? 1 : 0)} ${u[i]}`;
  };
  const fmtDur = (s) => {
    if (s == null) return "—";
    s = Math.max(0, Math.round(s));
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${sec}s` : `${sec}s`;
  };
  const num = (n) => (n == null ? "—" : Number(n).toLocaleString());
  const short = (id, a = 10, b = 6) => (id && id.length > a + b + 1 ? `${id.slice(0, a)}…${id.slice(-b)}` : id || "—");
  const copyBtn = (text) => `<button class="copy" type="button" data-copy="${esc(text)}">copy</button>`;
  const codeCopy = (text) => `<code>${esc(text)}</code> ${copyBtn(text)}`;
  const addrList = (list, empty = "None") => list?.length
    ? `<ul class="addrs">${list.map((a) => `<li><code>${esc(a)}</code>${copyBtn(a)}</li>`).join("")}</ul>`
    : `<p class="none">${esc(empty)}</p>`;
  const kv = (rows) => `<dl class="kv">${rows.filter(Boolean).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const errOr = (sec, fn, off = "Not running on this node.") =>
    sec == null ? `<p class="none">${esc(off)}</p>` : sec.error ? `<p class="none">Unavailable: ${esc(sec.error)}</p>` : fn(sec);
  const pill = (cls, text) => `<span class="pill ${cls}">${text}</span>`;
  const reachPill = (r) => pill(r === "public" ? "ok" : r === "private" ? "warn" : "mute", esc(r || "unknown"));
  const reachClass = (d) => {
    const r = d?.addresses?.reachability;
    return r === "public" ? "dot ok" : d?.sharing?.ready ? "dot warn" : (d?.peers?.total ?? 0) === 0 ? "dot bad" : "dot";
  };
  const humanKey = (k) => k.replace(/_/g, " ");
  const dim = (s) => `<span class="none">${s}</span>`;

  async function copyText(btn) {
    try { await navigator.clipboard.writeText(btn.dataset.copy); btn.textContent = "copied"; }
    catch { btn.textContent = "select"; }
    setTimeout(() => (btn.textContent = "copy"), 1200);
  }

  let ipfsTimer = null;
  let peerFilter = "";
  function stopIpfsRefresh() { clearTimeout(ipfsTimer); ipfsTimer = null; }
  const paintReach = (d) => $$("[data-reach]").forEach((el) => (el.className = reachClass(d)));
  async function refreshReachDot() {
    try { paintReach(await api("ipfs")); } catch { /* server busy or restarting */ }
  }

  async function renderIpfs(stale) {
    topbar.hidden = false;
    setQuery("");
    document.title = "IPFS node · Open Domain Catalog";
    view.innerHTML = `<section class="ipfs">
      <div class="ipfs-head"><div><h1>IPFS node</h1>
        <p>The basilisk-ipfs peer inside this explorer: how it reads the catalog, and how it shares blocks with other readers.</p></div>
        <span class="live"><span class="dot" id="live-dot"></span><span id="live-text">Connecting…</span></span></div>
      <div class="tiles" id="tiles">${`<div class="tile"><div class="skel w50"></div><div class="skel w70 tall"></div></div>`.repeat(6)}</div>
      <div class="dash">
        <div class="panel" id="p-node"><h2>Node</h2>${skeleton()}</div>
        <div class="panel" id="p-ipns"><h2>Catalog root (IPNS)</h2>${skeleton()}</div>
        <div class="panel wide" id="p-addrs"><h2>Addresses &amp; reachability</h2>${skeleton()}</div>
        <div class="panel" id="p-nat"><h2>NAT traversal</h2></div>
        <div class="panel" id="p-net"><h2>DHT &amp; Bitswap</h2></div>
        <div class="panel" id="p-repo"><h2>Repository</h2></div>
        <div class="panel" id="p-share-sum"><h2>Block sharing</h2></div>
        <div class="panel wide"><h2>Connected peers <small id="peer-count"></small></h2>
          <input class="filter" id="peer-filter" type="search" placeholder="Filter peers, addresses, agents" value="${esc(peerFilter)}" aria-label="Filter peers">
          <div class="tbl-wrap scroll" id="p-peers"></div></div>
        <div class="panel wide"><h2>Shared catalog blocks <small id="share-count"></small></h2>
          <div class="tbl-wrap scroll" id="p-share"></div></div>
      </div></section>`;
    let last = null;
    $("#peer-filter").addEventListener("input", (e) => { peerFilter = e.target.value; if (last) drawPeers(last.peers); });

    const tick = async () => {
      let d;
      try { d = await api("ipfs"); } catch (e) {
        if (stale()) return;
        $("#live-dot").className = "dot bad";
        $("#live-text").textContent = `Can't reach the explorer: ${e.message}`;
        ipfsTimer = setTimeout(tick, 5000);
        return;
      }
      if (stale()) return;
      last = d;
      paintReach(d);
      $("#live-dot").className = "dot ok";
      $("#live-text").textContent = `Live · updated ${new Date().toLocaleTimeString()} · refreshes every 5s`;
      if (!d.available) { $(".dash").innerHTML = `<div class="empty wide">No IPFS node is attached.</div>`; return; }
      drawAll(d);
      ipfsTimer = setTimeout(tick, 5000);
    };
    await tick();

    function reachSummary(a) {
      const pub = a?.public || [];
      const direct = pub.filter((x) => !x.includes("p2p-circuit")).length, relayed = pub.length - direct;
      if (a?.reachability === "private" || (!direct && relayed)) {
        return relayed ? `reachable via ${plural(relayed, "relay address", "relay addresses")}` : "not reachable yet";
      }
      return direct ? `${plural(direct, "direct public address", "direct public addresses")}` : "no public address yet";
    }

    function drawAll(d) {
      const { node: n, addresses: a, peers: p, sharing: sh, repo: r, bitswap: bs, dht } = d;
      const tile = (k, v, sub = "") => `<div class="tile"><div class="k">${k}</div><div class="v">${v}</div><div class="sub">${sub}</div></div>`;
      const shOff = !sh || sh.error, bsOff = !bs || bs.error, rOff = !r || r.error;
      $("#tiles").innerHTML = [
        tile("Reachability", reachPill(a?.reachability), reachSummary(a)),
        tile("Peers", num(p?.total), p?.error ? "" : `${p.inbound} in · ${p.outbound} out · ${p.relayed} relayed`),
        tile("DHT table", num(dht?.routing_table), dht ? `${esc(dht.mode)} mode` : "DHT off"),
        tile("Shared blocks", shOff ? "—" : `${num(sh.announced)}<span class="v-of">/${num(sh.blocks)}</span>`,
          shOff ? "announcing is off" : sh.ready ? `${num(sh.due)} due to announce` : "waiting for a reachable address"),
        tile("Bitswap", bsOff ? "—" : `${num(bs.stats.blocks_sent)} <span class="v-unit">sent</span>`,
          bsOff ? "" : `${fmtBytes(bs.stats.data_sent)} out · ${num(bs.stats.blocks_received)} blocks / ${fmtBytes(bs.stats.data_received)} in`),
        tile("Repository", rOff ? "—" : fmtBytes(r.size), rOff ? "" : `${num(r.num_blocks)} blocks${r.storage_max ? ` of ${fmtBytes(r.storage_max)}` : ""}`),
      ].join("");

      $("#p-node").innerHTML = `<h2>Node</h2>` + errOr(n, (n) => kv([
        ["Peer ID", codeCopy(n.peer_id)],
        ["Agent", esc(n.agent_version)],
        ["Protocol", esc(n.protocol_version)],
        ["Identity key", esc(n.key_type)],
        ["Crypto backend", esc(n.crypto_backend)],
        ["Uptime", fmtDur(n.uptime)],
        ["Repo", n.repo ? `<code>${esc(n.repo)}</code>` : "in memory"],
      ]) + `<h3>Protocols served</h3><div class="chipset">${n.protocols.map((x) => `<code>${esc(x)}</code>`).join("")}</div>`);

      $("#p-ipns").innerHTML = `<h2>Catalog root (IPNS)</h2>` + errOr(d.ipns, (ip) => kv([
        ["IPNS name", codeCopy(ip.name)],
        ["Current root", ip.root ? codeCopy(ip.root) : dim("not resolved yet")],
        ["Sequence", ip.sequence != null ? num(ip.sequence) : dim("unknown")],
        ["Previous root", ip.previous ? `<code>${esc(ip.previous)}</code>` : dim("none (first root)")],
        ["Resolved", ip.resolved_ago != null ? `${fmtDur(ip.resolved_ago)} ago` : dim("using last known root")],
        ["Next check", ip.next_check_in != null ? `in ${fmtDur(ip.next_check_in)}` : "—"],
        ip.resolve_error ? ["Last error", `${pill("bad", "error")} ${esc(ip.resolve_error)}`] : null,
      ]));

      const addrBlock = (title, list, empty) => `<div><h3>${title}</h3>${addrList(list, empty)}</div>`;
      $("#p-addrs").innerHTML = `<h2>Addresses &amp; reachability <small>${reachPill(a?.reachability)}</small></h2>` + errOr(a, (a) => `
        <div class="dash addr-grid">
          ${addrBlock("Announced to peers", a.announced, "Nothing announced yet")}
          ${addrBlock("Public (confirmed)", a.public, "No confirmed public address")}
          ${addrBlock("Listening on", a.listen)}
          ${addrBlock("Observed by peers", a.observed, "No observations yet")}
          ${addrBlock("Mapped on router (UPnP / NAT-PMP)", a.nat_mapped, "No router mapping")}
          ${addrBlock("Relay (p2p-circuit)", a.relay, "No relay addresses")}
          ${addrBlock("AutoNAT: reachable", a.verified, "None confirmed")}
          ${addrBlock("AutoNAT: unreachable", a.unreachable, "None")}
        </div>`);

      $("#p-nat").innerHTML = `<h2>NAT traversal</h2>
        <h3>Router port mapping</h3>${errOr(d.nat, (x) => kv([
          ["Gateway", x.gateway ? `${esc(x.gateway)}${x.gateway_host ? ` <code>${esc(x.gateway_host)}</code>` : ""}` : dim("searching / none found")],
          ["External IP", x.external_ip ? `<code>${esc(x.external_ip)}</code>` : "—"],
          ["Mappings", x.mappings.length ? x.mappings.map((m) => `<code>${m.internal} → ${m.external}</code>`).join(" ") : "none"],
        ]), "Not active (needs a public listen address).")}
        <h3>AutoNAT</h3>${errOr(d.autonat, (x) => x.results.length
          ? `<div class="tbl-wrap"><table class="tbl"><tr><th>Address</th><th class="num">Reachable</th><th class="num">Unreachable</th></tr>${x.results.map((r) =>
              `<tr><td><code>${esc(r.addr)}</code></td><td class="num">${r.reachable}</td><td class="num">${r.unreachable}</td></tr>`).join("")}</table></div>
             <p class="none note">${x.confidence} agreeing servers needed for a verdict.</p>`
          : dim("No dial-back results yet."))}
        <h3>Circuit relay</h3>${errOr(d.relay, (x) => kv([
          ["Client mode", esc(x.mode)],
          ["Relay service", x.service ? "on" : "off"],
          ["Reservations", x.reservations.length ? "" : "none"],
        ]) + (x.reservations.length ? `<ul class="addrs">${x.reservations.map((rv) =>
          `<li><code>${esc(rv.relay)}</code>${dim(rv.expires_in != null ? `expires in ${fmtDur(rv.expires_in)}` : "")}</li>`).join("")}</ul>` : ""))}
        <h3>Hole punching (DCUtR)</h3>${errOr(d.hole_punch, (x) => kv(Object.entries(x).map(([k, v]) => [humanKey(k), num(v)])))}`;

      $("#p-net").innerHTML = `<h2>DHT &amp; Bitswap</h2>
        <h3>Kademlia DHT</h3>${errOr(dht, (x) => kv([
          ["Protocol", `<code>${esc(x.protocol)}</code>`],
          ["Mode", `${esc(x.mode)} ${dim("(queries the DHT; doesn't answer queries)")}`],
          ["Routing table", `${num(x.routing_table)} peers`],
          ["Bootstrap peers", num(x.bootstrap_peers)],
        ]), "DHT disabled.")}
        <h3>Bitswap</h3>${errOr(bs, (x) => kv([
          ["Serving blocks", x.serving ? pill("ok", "on") : pill("bad", "off")],
          ["Blocks sent", `${num(x.stats.blocks_sent)} · ${fmtBytes(x.stats.data_sent)}`],
          ["Blocks received", `${num(x.stats.blocks_received)} · ${fmtBytes(x.stats.data_received)}`],
          ["Duplicate blocks", num(x.stats.dup_blocks)],
          ["Our open wants", num(x.our_wants)],
          ["Peers wanting blocks", `${num(x.peers_wanting)} ${dim(`(${num(x.blocks_wanted_by_peers)} blocks)`)}`],
        ]))}`;

      $("#p-repo").innerHTML = `<h2>Repository</h2>` + errOr(r, (x) => {
        const pct = x.storage_max ? Math.min(100, (100 * x.size) / x.storage_max) : null;
        const skip = new Set(["size", "storage_max", "num_blocks", "pins"]);
        const fmt = (k, v) => /size|bytes|water/.test(k) && typeof v === "number" && v > 1 ? fmtBytes(v) : typeof v === "number" ? num(v) : esc(String(v));
        return (pct != null ? `<div class="meter"><i style="width:${pct.toFixed(1)}%"></i></div>
            <p class="none meter-note">${fmtBytes(x.size)} of ${fmtBytes(x.storage_max)} (${pct.toFixed(1)}%). Least-recently-used unpinned blocks are evicted when full.</p>` : "") +
          kv([["Blocks", num(x.num_blocks)], ["Pins", num(x.pins)],
              ...Object.entries(x).filter(([k]) => !skip.has(k)).map(([k, v]) => [humanKey(k), fmt(k, v)])]);
      }) + `<h3>Block cache (memory)</h3>` + errOr(d.block_cache, (c) => {
        const reads = c.hits + c.misses;
        return kv([
          ["Holding", `${num(c.blocks)} blocks · ${fmtBytes(c.bytes)} of ${fmtBytes(c.max_bytes)}`],
          ["Hit rate", reads ? `${((100 * c.hits) / reads).toFixed(1)}% ${dim(`(${num(c.hits)} hits, ${num(c.misses)} misses)`)}` : "no reads yet"],
          ["Evicted", num(c.evictions)],
        ]) + `<p class="none note">Parsed blocks, by CID, shared across catalog versions. basilisk-ipfs manages the copies on disk.</p>`;
      });

      $("#p-share-sum").innerHTML = `<h2>Block sharing <small>by basilisk-ipfs</small></h2>` + errOr(sh, (x) => kv([
        ["Status", x.ready ? pill("ok", "announcing") : `${pill("warn", "waiting")} ${dim("for a public or relay address (up to 3 min)")}`],
        ["Strategy", `<code>${esc(x.strategy)}</code> ${dim("(every cached block)")}`],
        ["Blocks held", num(x.blocks)],
        ["Announced", num(x.announced)],
        ["Due now", num(x.due)],
        x.retrying ? ["Retrying", `${num(x.retrying)} ${dim("(backing off after failures)")}`] : null,
        ["Re-announce", `every ${fmtDur(x.interval)}`],
        ["Last pass", x.last_pass_ago != null ? `${fmtDur(x.last_pass_ago)} ago, took ${fmtDur(x.last_pass_duration)}` : "not yet"],
        ["Totals", `${num(x.provided_total)} announced · ${num(x.failed_total)} failed · ${num(x.passes)} passes`],
        ["Parallel announces", num(x.workers)],
      ]) + `<p class="none note">Every block in this reader's cache is served over Bitswap and announced on the DHT by basilisk-ipfs, so other readers can fetch it from here.</p>`,
      "Announcing is off on this node.");

      drawPeers(p);
      $("#share-count").textContent = shOff ? "" : `${plural(sh.blocks, "block", "blocks")}${sh.list.length < sh.blocks ? ` (showing ${sh.list.length})` : ""}`;
      $("#p-share").innerHTML = errOr(sh, (x) => x.list.length
        ? `<table class="tbl"><tr><th>Block CID</th><th>Announced</th><th>Next re-announce</th></tr>${x.list.map((b) =>
            `<tr><td>${codeCopy(b.cid)}</td><td class="num">${b.announced_ago != null ? `${fmtDur(b.announced_ago)} ago`
              : b.retry_in != null ? pill("bad", `failed ×${b.failures}`) : pill("warn", "pending")}</td>
             <td class="num">${b.next_in != null ? `in ${fmtDur(b.next_in)}` : b.retry_in != null ? `retry in ${fmtDur(b.retry_in)}` : "—"}</td></tr>`).join("")}</table>`
        : dim("No catalog blocks fetched yet. Browse a shelf and they'll appear here."));
    }

    function drawPeers(p) {
      if (!p || p.error) { $("#p-peers").innerHTML = errOr(p, () => ""); return; }
      const f = peerFilter.trim().toLowerCase();
      const rows = f ? p.list.filter((c) => `${c.peer} ${c.addr} ${c.agent} ${c.direction}`.toLowerCase().includes(f)) : p.list;
      $("#peer-count").textContent = `${num(p.total)} peers · ${num(p.connections)} connections · ${num(p.known)} known${f ? ` · ${rows.length} shown` : ""}`;
      $("#p-peers").innerHTML = rows.length ? `<table class="tbl"><tr><th>Peer</th><th>Address</th><th>Dir</th><th>Type</th><th>Agent</th><th class="num">Connected</th></tr>${rows.map((c) => `
        <tr><td><code title="${esc(c.peer)}">${esc(short(c.peer))}</code>${c.dht ? ` <span class="pill mute" title="In the DHT routing table">dht</span>` : ""}</td>
          <td><code>${esc(c.addr || "—")}</code></td>
          <td>${c.direction === "inbound" ? "in" : "out"}</td>
          <td>${c.relayed ? pill("warn", c.limited ? "relay (limited)" : "relay") : "direct"}</td>
          <td>${esc(c.agent || "—")}</td>
          <td class="num">${fmtDur(c.age)}</td></tr>`).join("")}</table>`
        : dim(f ? "No peers match the filter." : "No connections yet.");
    }
  }

  // ---------- project links (spec Sections 4.1 and 8) ----------
  // Read from the current root on every catalog response and shown as plain,
  // quiet text at the bottom of the sidebar, in ODC's order with ODC's labels.
  // Only http(s) URLs are rendered, since the URLs come from the catalog.
  let projectLinks = [], linksKey = null;
  const safeUrl = (u) => { try { return ["http:", "https:"].includes(new URL(u).protocol); } catch { return false; } };
  const linkTag = (l, cls = "", donate = false) =>
    `<a class="${cls}" href="${esc(l.url)}" target="_blank" rel="noopener noreferrer"${donate ? ' data-donate="give"' : ""}>${esc(l.label)}</a>`;
  const railLinks = () => projectLinks.map((l) => linkTag(l)).join("");
  function setProjectLinks(links) {
    const key = JSON.stringify(links);
    if (key === linksKey) return;
    linksKey = key;
    projectLinks = links.filter((l) => l.label && safeUrl(l.url));
    const box = $("#rail-links");
    if (box) box.innerHTML = railLinks();
    const donate = projectLinks.find((l) => l.label.trim().toLowerCase() === DONATE_LABEL);
    if (donatePending && donate) { donatePending = false; showDonate(donate); }
  }

  // ---------- donation banner ----------
  // Shown when the page opens, unless this browser answered it within the last
  // DONATE_EVERY_MONTHS calendar months. Its button is the root's project link
  // labelled "Donate", so it waits until the links are known and isn't shown if
  // there is no such link. Any answer (donate, already donated, not now) starts
  // the wait.
  const donateBox = $("#donate");
  let donatePending = false;
  function donateDue(now = new Date()) {
    const answered = Number(store.get("odc-donate-answered"));
    if (!answered) return true;
    const next = new Date(answered);
    next.setMonth(next.getMonth() + DONATE_EVERY_MONTHS);
    return now >= next;
  }
  function showDonate(donate) {
    donateBox.innerHTML = `<div class="donate-inner">
      <span class="mark" aria-hidden="true"><i></i><i></i><i></i></span>
      <div class="donate-text">
        <p class="eyebrow">A quick ask</p>
        <h2>Help keep the web's library open.</h2>
        <p>The Open Domain Catalog is curated by hand and free for everyone: no ads, no tracking,
          nothing to sell you. Keeping it growing takes time and money, and readers make that possible.
          If the catalog has helped you find something worth finding, please chip in.</p>
      </div>
      <div class="donate-actions">
        ${linkTag({ ...donate, label: "Donate" }, "btn primary", true)}
        <button class="btn" type="button" data-donate="already">I've already donated</button>
        <button class="btn quiet" type="button" data-donate="decline">Not now</button>
      </div>
    </div>`;
    donateBox.hidden = false;
  }
  function answerDonate(answer) {
    if (answer === "close") { donateBox.hidden = true; return; }
    store.set("odc-donate-answered", String(Date.now()));
    if (answer === "decline") { donateBox.hidden = true; return; }
    donateBox.innerHTML = `<div class="donate-inner thanks">
      <span class="mark" aria-hidden="true"><i></i><i></i><i></i></span>
      <div class="donate-text"><h2>Thank you.</h2><p>Readers like you are why the catalog stays open.</p></div>
      <div class="donate-actions"><button class="btn" type="button" data-donate="close">Close</button></div>
    </div>`;
  }

  // ---------- start ----------
  syncAdultToggles();
  donatePending = donateDue();
  route();
  // Project links (for the donation banner) even on pages that don't read the catalog.
  api("category", { call: "", hide: hideParam() }).then((c) => noteRoot(c.root, c.links)).catch(() => {});
  refreshReachDot();
  setInterval(refreshReachDot, 60000);
})();
