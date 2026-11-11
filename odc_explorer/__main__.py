"""python -m odc_explorer [--host HOST] [--port 8181] [--repo PATH] [--open] [--debug]

Or use run.sh from a checkout, or the commands that install.sh sets up.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import webbrowser

from .platform_compat import PortInUse, default_repo, ensure_port_free


STOP_TIMEOUT = 10   # seconds to let the IPFS node stop before exiting


def _stop_on_signal(signum, frame):
    raise KeyboardInterrupt


def _install_signal_handlers():
    """Let Ctrl+C, SIGTERM (Linux service managers, kill), SIGHUP (terminal
    closed, Linux) and Ctrl+Break / console close (Windows) all shut down
    cleanly, stopping the IPFS node."""
    signal.signal(signal.SIGINT, signal.default_int_handler)   # even if inherited as ignored
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop_on_signal)


def main():
    ap = argparse.ArgumentParser(description="Open Domain Catalog chain explorer")
    ap.add_argument("--host", default="127.0.0.1",
                    help="interface for the web UI (0.0.0.0 to allow other machines)")
    ap.add_argument("--port", type=int, default=8181, help="web UI port")
    ap.add_argument("--repo", default=None,
                    help=f"block cache, node identity and state (default: {default_repo()})")
    ap.add_argument("--open", action="store_true", help="open the explorer in your web browser")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    for noisy in ("basilisk_ipfs", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Fail fast, before the IPFS node starts, if the web port is taken.
    try:
        ensure_port_free(args.host, args.port, "web UI")
    except PortInUse as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    from .app import create_app
    from .service import Explorer
    try:
        explorer = Explorer(args.repo or default_repo())
    except PortInUse as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    _install_signal_handlers()
    app = create_app(explorer)
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{shown}:{args.port}/"
    print(f"ODC explorer on {url}  (data: {explorer.repo})")
    print("Press Ctrl+C to stop.")
    if args.open:
        threading.Timer(1.0, webbrowser.open, (url,)).start()
    try:
        app.run(host=args.host, port=args.port, threaded=True, debug=False)
    except KeyboardInterrupt:
        pass
    finally:
        print("Stopping IPFS node...", flush=True)
        # Give the node a bounded time to stop cleanly, then exit without
        # waiting for basilisk-ipfs worker threads that may be mid-way through DHT
        # lookups (an announcement pass can take minutes). basilisk-ipfs saves its
        # announcement progress in batches, so at worst a few are redone.
        stopper = threading.Thread(target=explorer.close, daemon=True)
        stopper.start()
        stopper.join(STOP_TIMEOUT)
        if stopper.is_alive():
            print(f"IPFS node still stopping after {STOP_TIMEOUT}s; exiting anyway.", flush=True)
        logging.shutdown()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
