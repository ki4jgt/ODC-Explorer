"""OpenSSL (libcrypto) backend via ctypes for ChaCha20-Poly1305, X25519 and
Ed25519, roughly 100x faster than the pure-Python code.

ctypes is in the standard library; libcrypto is the same library Python's
``ssl`` module uses. If it can't be found, is older than 1.1.1, or fails the
self-test against RFC vectors, ``AVAILABLE`` is False and callers keep the
pure-Python implementations. Set ``BASILISK_IPFS_PURE_PYTHON=1`` to force that.
"""

import ctypes
import ctypes.util
import os
import sys

AVAILABLE = False
VERSION = None
ERROR = None
LIB = None  # the loaded libcrypto (ctypes.CDLL), shared with the QUIC transport

_EVP_PKEY_X25519 = 1034
_EVP_PKEY_ED25519 = 1087
_CTRL_AEAD_GET_TAG = 0x10
_CTRL_AEAD_SET_TAG = 0x11
_MAX_UPDATE = 1 << 30

_P = ctypes.c_void_p
_I = ctypes.c_int
_SZ = ctypes.c_size_t
_BUF = ctypes.c_char_p


def _candidates():
    # 1. the libcrypto already mapped into this process by the ssl module (Linux)
    try:
        import _ssl  # noqa: F401  (loads libcrypto)
        with open("/proc/self/maps") as f:
            for line in f:
                path = line.rsplit(None, 1)[-1]
                if "/libcrypto" in path and ".so" in path:
                    yield path
    except (ImportError, OSError):
        pass
    if sys.platform == "darwin":
        # never load the unversioned system libcrypto: macOS aborts the process
        for prefix in ("/opt/homebrew/opt/openssl@3", "/usr/local/opt/openssl@3",
                       "/opt/homebrew/opt/openssl@1.1", "/usr/local/opt/openssl@1.1"):
            for name in ("libcrypto.3.dylib", "libcrypto.1.1.dylib"):
                yield os.path.join(prefix, "lib", name)
        return
    if sys.platform == "win32":
        yield from ("libcrypto-3-x64", "libcrypto-3", "libcrypto-1_1-x64", "libcrypto-1_1")
    yield from ("libcrypto.so.3", "libcrypto.so.1.1")
    found = ctypes.util.find_library("crypto")
    if found:
        yield found


def _bind(lib):
    def fn(name, restype, *argtypes):
        f = getattr(lib, name)
        f.restype = restype
        f.argtypes = list(argtypes)
        return f

    g = {}
    g["cipher_ctx_new"] = fn("EVP_CIPHER_CTX_new", _P)
    g["cipher_ctx_free"] = fn("EVP_CIPHER_CTX_free", None, _P)
    g["chacha"] = fn("EVP_chacha20_poly1305", _P)
    for d in ("Encrypt", "Decrypt"):
        g[d + "Init"] = fn(f"EVP_{d}Init_ex", _I, _P, _P, _P, _BUF, _BUF)
        g[d + "Update"] = fn(f"EVP_{d}Update", _I, _P, _P, ctypes.POINTER(_I), _BUF, _I)
        g[d + "Final"] = fn(f"EVP_{d}Final_ex", _I, _P, _P, ctypes.POINTER(_I))
    g["ctrl"] = fn("EVP_CIPHER_CTX_ctrl", _I, _P, _I, _I, _P)
    g["new_priv"] = fn("EVP_PKEY_new_raw_private_key", _P, _I, _P, _BUF, _SZ)
    g["new_pub"] = fn("EVP_PKEY_new_raw_public_key", _P, _I, _P, _BUF, _SZ)
    g["get_pub"] = fn("EVP_PKEY_get_raw_public_key", _I, _P, _P, ctypes.POINTER(_SZ))
    g["pkey_free"] = fn("EVP_PKEY_free", None, _P)
    g["pctx_new"] = fn("EVP_PKEY_CTX_new", _P, _P, _P)
    g["pctx_free"] = fn("EVP_PKEY_CTX_free", None, _P)
    g["derive_init"] = fn("EVP_PKEY_derive_init", _I, _P)
    g["derive_peer"] = fn("EVP_PKEY_derive_set_peer", _I, _P, _P)
    g["derive"] = fn("EVP_PKEY_derive", _I, _P, _P, ctypes.POINTER(_SZ))
    g["md_new"] = fn("EVP_MD_CTX_new", _P)
    g["md_free"] = fn("EVP_MD_CTX_free", None, _P)
    g["sign_init"] = fn("EVP_DigestSignInit", _I, _P, _P, _P, _P, _P)
    g["sign"] = fn("EVP_DigestSign", _I, _P, _P, ctypes.POINTER(_SZ), _BUF, _SZ)
    g["verify_init"] = fn("EVP_DigestVerifyInit", _I, _P, _P, _P, _P, _P)
    g["verify"] = fn("EVP_DigestVerify", _I, _P, _BUF, _SZ, _BUF, _SZ)
    g["err_clear"] = fn("ERR_clear_error", None)
    try:
        ver = fn("OpenSSL_version", _BUF, _I)
        g["version"] = ver(0).decode()
    except AttributeError:
        g["version"] = "OpenSSL (unknown version)"
    return g


_f = None


class InvalidTag(Exception):
    pass


# ---- ChaCha20-Poly1305 --------------------------------------------------------
def _aead(encrypt, key, nonce, data, aad, tag=None):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 needs a 32-byte key and 12-byte nonce")
    d = "Encrypt" if encrypt else "Decrypt"
    ctx = _f["cipher_ctx_new"]()
    if not ctx:
        raise MemoryError("EVP_CIPHER_CTX_new failed")
    try:
        if _f[d + "Init"](ctx, _f["chacha"](), None, bytes(key), bytes(nonce)) != 1:
            raise ValueError("cipher init failed")
        n = _I()
        if aad:
            aad = bytes(aad)
            for i in range(0, len(aad), _MAX_UPDATE):
                part = aad[i:i + _MAX_UPDATE]
                if _f[d + "Update"](ctx, None, ctypes.byref(n), part, len(part)) != 1:
                    raise ValueError("AAD update failed")
        data = bytes(data)
        out = ctypes.create_string_buffer(len(data) + 16)
        pos = 0
        for i in range(0, len(data), _MAX_UPDATE):
            part = data[i:i + _MAX_UPDATE]
            if _f[d + "Update"](ctx, ctypes.byref(out, pos), ctypes.byref(n), part, len(part)) != 1:
                raise ValueError("cipher update failed")
            pos += n.value
        if tag is not None:
            tbuf = ctypes.create_string_buffer(bytes(tag), 16)
            if _f["ctrl"](ctx, _CTRL_AEAD_SET_TAG, 16, tbuf) != 1:
                raise ValueError("set tag failed")
        if _f[d + "Final"](ctx, ctypes.byref(out, pos), ctypes.byref(n)) != 1:
            _f["err_clear"]()
            raise InvalidTag("authentication failed")
        pos += n.value
        result = out.raw[:pos]
        if encrypt:
            tbuf = ctypes.create_string_buffer(16)
            if _f["ctrl"](ctx, _CTRL_AEAD_GET_TAG, 16, tbuf) != 1:
                raise ValueError("get tag failed")
            result += tbuf.raw
        return result
    finally:
        _f["cipher_ctx_free"](ctx)


def aead_encrypt(key, nonce, plaintext, aad=b""):
    return _aead(True, key, nonce, plaintext, aad)


def aead_decrypt(key, nonce, ciphertext, aad=b""):
    if len(ciphertext) < 16:
        raise InvalidTag("ciphertext too short")
    return _aead(False, key, nonce, ciphertext[:-16], aad, ciphertext[-16:])


# ---- raw keys -------------------------------------------------------------
def _pkey(kind, private, raw):
    if len(raw) != 32:
        raise ValueError("key must be 32 bytes")
    k = (_f["new_priv"] if private else _f["new_pub"])(kind, None, bytes(raw), 32)
    if not k:
        _f["err_clear"]()
        raise ValueError("invalid key")
    return k


def _public_of(kind, priv):
    k = _pkey(kind, True, priv)
    try:
        out = ctypes.create_string_buffer(32)
        ln = _SZ(32)
        if _f["get_pub"](k, out, ctypes.byref(ln)) != 1 or ln.value != 32:
            raise ValueError("could not derive public key")
        return out.raw
    finally:
        _f["pkey_free"](k)


# ---- X25519 ---------------------------------------------------------------
def x25519_public(priv):
    return _public_of(_EVP_PKEY_X25519, priv)


def x25519_shared(priv, peer_pub):
    a = _pkey(_EVP_PKEY_X25519, True, priv)
    b = c = None
    try:
        b = _pkey(_EVP_PKEY_X25519, False, peer_pub)
        c = _f["pctx_new"](a, None)
        out = ctypes.create_string_buffer(32)
        ln = _SZ(32)
        if (not c or _f["derive_init"](c) != 1 or _f["derive_peer"](c, b) != 1
                or _f["derive"](c, out, ctypes.byref(ln)) != 1):
            _f["err_clear"]()  # OpenSSL rejects low-order points (all-zero secret)
            raise ValueError("x25519 key agreement failed")
        if out.raw == b"\0" * 32:
            raise ValueError("x25519 produced all-zero shared secret")
        return out.raw
    finally:
        if c:
            _f["pctx_free"](c)
        if b:
            _f["pkey_free"](b)
        _f["pkey_free"](a)


# ---- Ed25519 --------------------------------------------------------------
def ed25519_public(seed):
    return _public_of(_EVP_PKEY_ED25519, seed)


def ed25519_sign(seed, msg):
    k = _pkey(_EVP_PKEY_ED25519, True, seed)
    md = _f["md_new"]()
    try:
        msg = bytes(msg)
        sig = ctypes.create_string_buffer(64)
        ln = _SZ(64)
        if (not md or _f["sign_init"](md, None, None, None, k) != 1
                or _f["sign"](md, sig, ctypes.byref(ln), msg, len(msg)) != 1):
            _f["err_clear"]()
            raise ValueError("ed25519 signing failed")
        return sig.raw[:ln.value]
    finally:
        if md:
            _f["md_free"](md)
        _f["pkey_free"](k)


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    try:
        k = _pkey(_EVP_PKEY_ED25519, False, public)
    except ValueError:
        return False
    md = _f["md_new"]()
    try:
        msg = bytes(msg)
        ok = (md and _f["verify_init"](md, None, None, None, k) == 1
              and _f["verify"](md, bytes(sig), 64, msg, len(msg)) == 1)
        if not ok:
            _f["err_clear"]()
        return bool(ok)
    finally:
        if md:
            _f["md_free"](md)
        _f["pkey_free"](k)


# ---- loading & self-test ----------------------------------------------------------
def _self_test():
    # RFC 8439 2.8.2
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
          b"for the future, sunscreen would be it.")
    ct = aead_encrypt(key, nonce, pt, aad)
    assert ct[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"
    assert aead_decrypt(key, nonce, ct, aad) == pt
    bad = bytearray(ct)
    bad[0] ^= 1
    try:
        aead_decrypt(key, nonce, bytes(bad), aad)
        raise AssertionError("tampered ciphertext accepted")
    except InvalidTag:
        pass
    # RFC 7748 6.1
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519_public(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert x25519_shared(a, b_pub).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    # RFC 8032 7.1 test 2
    sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk = ed25519_public(sk)
    assert pk.hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    sig = ed25519_sign(sk, b"\x72")
    assert sig.hex() == ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    assert ed25519_verify(pk, b"\x72", sig) and not ed25519_verify(pk, b"\x73", sig)


def _load():
    global _f, AVAILABLE, VERSION, ERROR, LIB
    if os.environ.get("BASILISK_IPFS_PURE_PYTHON"):
        ERROR = "disabled by BASILISK_IPFS_PURE_PYTHON"
        return
    errors = []
    for cand in dict.fromkeys(_candidates()):
        try:
            lib = ctypes.CDLL(cand)
            _f = _bind(lib)
            _self_test()
        except Exception as e:  # missing symbols (too old), wrong results, not found
            errors.append(f"{cand}: {e}")
            _f = None
            continue
        AVAILABLE = True
        VERSION = _f["version"]
        LIB = lib
        return
    ERROR = "; ".join(errors) or "libcrypto not found"


_load()
