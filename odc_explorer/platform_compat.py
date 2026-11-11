"""Small helpers that keep the explorer behaving the same on Windows and Linux."""

import os
import socket
import sys

WINDOWS = sys.platform == "win32"


class PortInUse(OSError):
    """A port the explorer needs is already taken by another program."""


def default_repo():
    """Where the block cache, node identity and state live by default.

    Windows: %LOCALAPPDATA%\\ODC Explorer (per-user, not roamed).
    Linux and others: ~/.odc-explorer
    """
    if WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "ODC Explorer")
    return os.path.join(os.path.expanduser("~"), ".odc-explorer")


def _probe(family, host, port):
    """Try to bind (host, port) the way a real listener would, then let it go."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if WINDOWS:
            # Windows' SO_REUSEADDR lets a second socket share a port that is
            # already listening; exclusive use makes this probe fail instead.
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        else:
            # On Linux SO_REUSEADDR only skips TIME_WAIT leftovers; a port with
            # an active listener still fails to bind.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        sock.listen(1)
    finally:
        sock.close()


def ensure_port_free(host, port, what):
    """Raise PortInUse with a readable message if (host, port) can't be bound."""
    if port == 0:
        return
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        _probe(family, host, port)
    except OSError as e:
        raise PortInUse(
            f"Port {port} ({what}) is already in use or not allowed: {e.strerror or e}. "
            f"Stop the other program, or pick another port.") from None
