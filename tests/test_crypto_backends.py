"""The OpenSSL (ctypes) and pure-Python crypto backends must agree exactly."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs.crypto import _openssl, chacha20poly1305 as aead, ed25519, x25519


@unittest.skipUnless(_openssl.AVAILABLE, f"OpenSSL backend unavailable: {_openssl.ERROR}")
class TestBackendsAgree(unittest.TestCase):
    def test_aead(self):
        for n in (0, 1, 15, 16, 17, 63, 64, 65, 1000, 65519, 300_000):
            key, nonce, aad = os.urandom(32), os.urandom(12), os.urandom(n % 40)
            pt = os.urandom(n)
            ct = aead.encrypt(key, nonce, pt, aad)
            self.assertEqual(ct, aead.py_encrypt(key, nonce, pt, aad), n)
            self.assertEqual(aead.decrypt(key, nonce, ct, aad), pt)
            self.assertEqual(aead.py_decrypt(key, nonce, ct, aad), pt)

    def test_aead_rejects_tampering(self):
        key, nonce = os.urandom(32), os.urandom(12)
        ct = aead.encrypt(key, nonce, b"attack at dawn", b"hdr")
        for i in (0, len(ct) - 1):  # ciphertext byte, tag byte
            bad = bytearray(ct)
            bad[i] ^= 1
            with self.assertRaises(aead.InvalidTag):
                aead.decrypt(key, nonce, bytes(bad), b"hdr")
        with self.assertRaises(aead.InvalidTag):
            aead.decrypt(key, nonce, ct, b"other aad")
        with self.assertRaises(aead.InvalidTag):
            aead.decrypt(key, nonce, ct[:10])

    def test_x25519(self):
        for _ in range(20):
            a, b = os.urandom(32), os.urandom(32)
            self.assertEqual(x25519.public_key(a), x25519.py_public_key(a))
            pb_ = x25519.py_public_key(b)
            self.assertEqual(x25519.shared(a, pb_), x25519.py_shared(a, pb_))

    def test_x25519_low_order_point_rejected(self):
        for backend in (x25519.shared, x25519.py_shared):
            with self.assertRaises(ValueError):
                backend(os.urandom(32), b"\0" * 32)

    def test_ed25519(self):
        for n in (0, 1, 56, 1000):
            seed, msg = os.urandom(32), os.urandom(n)
            pk = ed25519.public_key(seed)
            self.assertEqual(pk, ed25519.py_public_key(seed))
            sig = ed25519.sign(seed, msg)
            self.assertEqual(sig, ed25519.py_sign(seed, msg))  # deterministic
            self.assertTrue(ed25519.verify(pk, msg, sig))
            self.assertTrue(ed25519.py_verify(pk, msg, sig))
            bad = bytearray(sig)
            bad[5] ^= 1
            self.assertFalse(ed25519.verify(pk, msg, bytes(bad)))
            self.assertFalse(ed25519.verify(pk, msg + b"x", sig))

    def test_ed25519_malformed_inputs(self):
        pk = ed25519.public_key(os.urandom(32))
        for public, sig in ((pk, b"\0" * 63), (pk[:31], b"\0" * 64), (b"\xff" * 32, b"\0" * 64)):
            self.assertFalse(ed25519.verify(public, b"m", sig))
        # s >= L must be rejected (malleability)
        seed = os.urandom(32)
        sig = ed25519.sign(seed, b"m")
        s = int.from_bytes(sig[32:], "little") + ed25519.L
        forged = sig[:32] + s.to_bytes(32, "little")
        self.assertFalse(ed25519.verify(ed25519.public_key(seed), b"m", forged))
        self.assertFalse(ed25519.py_verify(ed25519.public_key(seed), b"m", forged))


if __name__ == "__main__":
    unittest.main()
