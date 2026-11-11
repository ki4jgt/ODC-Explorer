"""Flask front end for the ODC chain explorer: the page and a small JSON API."""

import os

from flask import Flask, jsonify, request, render_template

from . import ipfs_status
from .chain import Hidden, NotFound, MalformedBlock, parse_call, fmt_call, PAGE_SIZE


class BadCall(ValueError):
    """A request parameter isn't a valid call number."""


# exception -> (HTTP status, error code, message template)
ERRORS = {
    BadCall: (400, "bad_call", "{} is not a call number (use 0-9 and A-Z, up to 9 characters)"),
    Hidden: (403, "hidden", "{} is hidden by your content settings"),
    NotFound: (404, "not_found", "No category {}"),
    MalformedBlock: (502, "malformed", "{}"),
    LookupError: (503, "unavailable", "{}"),   # e.g. the root isn't resolved yet
}

# The page may only load from this server (no third-party requests).
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "font-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; "
                               "form-action 'self'",
    "Referrer-Policy": "no-referrer",
}


def create_app(explorer):
    app = Flask(__name__)
    app.json.sort_keys = False

    for exc, (status, code, message) in ERRORS.items():
        app.register_error_handler(
            exc, lambda e, status=status, code=code, message=message:
            (jsonify(error=code, message=message.format(e)), status))

    def catalog():
        """The catalog at the latest published root (clients can't pin another)."""
        if explorer.root is None and not explorer.wait_ready(90):
            raise LookupError(explorer.resolve_error or "still resolving the ODC root over IPNS")
        return explorer.catalog()

    def call_arg(name, default=""):
        raw = request.args.get(name, default)
        bare = parse_call(raw)
        if bare is None:
            raise BadCall(repr(raw))
        return bare

    def hide_arg():
        # Comma-separated call numbers whose whole branch the reader doesn't
        # want to see (the 18+ switch sends ``hide=0``).
        return tuple(filter(None, map(parse_call, request.args.get("hide", "").split(","))))

    def asset_version():
        # Changes whenever app.js or app.css does, so a reload always fetches
        # the current front end rather than a copy the browser kept.
        paths = (os.path.join(app.static_folder, n) for n in ("app.js", "app.css"))
        return str(int(max((os.path.getmtime(p) for p in paths if os.path.exists(p)), default=0)))

    @app.get("/")
    def index():
        resp = app.make_response(render_template("index.html", v=asset_version()))
        resp.headers["Cache-Control"] = "no-store"   # never reuse a stored copy of the page
        return resp

    @app.get("/favicon.ico")
    def favicon():
        return app.send_static_file("favicon.ico")

    @app.get("/api/ipfs")
    def ipfs():
        return jsonify(ipfs_status.snapshot(explorer))

    @app.get("/api/category")
    def category():
        cat = catalog()
        return jsonify({**cat.category(call_arg("call"), hide_arg()), "root": cat.root, "links": cat.links()})

    @app.get("/api/flow")
    def flow():
        # ``from`` is where reading started (its subcategories, then later
        # siblings, onward to the end of the catalog); ``call`` + ``offset`` is
        # the cursor within that order. ``from`` defaults to ``call``.
        cat = catalog()
        call = call_arg("call")
        origin = call_arg("from", fmt_call(call))
        offset = max(0, request.args.get("offset", 0, type=int))
        page = cat.page(origin, call, offset, PAGE_SIZE, hide_arg())
        return jsonify({**page, "root": cat.root, "links": cat.links(), "origin": fmt_call(origin),
                        "start": {"call": fmt_call(call), "offset": offset}})

    @app.after_request
    def security_headers(resp):
        resp.headers.update(SECURITY_HEADERS)
        return resp

    return app
