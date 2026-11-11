"""Cryptographic primitives used by the libp2p stack.

ChaCha20-Poly1305, X25519 and Ed25519 use OpenSSL's libcrypto through ctypes
when it is available (about 100x faster), and fall back to the pure-Python
implementations otherwise. ``BACKEND`` says which is in use; set
``BASILISK_IPFS_PURE_PYTHON=1`` to force pure Python.
"""

from . import _openssl

BACKEND = _openssl.VERSION if _openssl.AVAILABLE else "pure-python"
