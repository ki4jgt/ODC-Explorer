"""libp2p QUIC transport: certificate handling (offline) and, with
BASILISK_IPFS_NETWORK_TESTS=1, a live dial to public QUIC peers."""

import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from basilisk_ipfs import Ed25519PrivateKey, Host, Multiaddr
from basilisk_ipfs.p2p import quic
from basilisk_ipfs.p2p.host import _order_addrs, dialable
from basilisk_ipfs.p2p.quic import _oid, _seq, _tlv, build_certificate, verify_certificate

NOW = datetime.datetime.now(datetime.timezone.utc)


def fake_spki():
    # any well-formed SubjectPublicKeyInfo works for the libp2p-level checks
    return _seq(_seq(_oid("1.2.840.10045.2.1"), _oid("1.2.840.10045.3.1.7")),
                _tlv(0x03, b"\x00\x04" + os.urandom(64)))


def signed_key_ext(identity, spki, signature=None, critical=False):
    sig = signature if signature is not None else identity.sign(quic.SIG_PREFIX + spki)
    value = _seq(_tlv(0x04, identity.public_key.to_protobuf()), _tlv(0x04, sig))
    crit = _tlv(0x01, b"\xff") if critical else b""
    return _seq(_oid(quic.EXTENSION_OID), crit, _tlv(0x04, value))


def cert(spki, extensions, now=NOW, lifetime=datetime.timedelta(days=365)):
    """A certificate with exactly the given extensions (the X.509 signature
    itself is checked by OpenSSL, not by verify_certificate)."""
    alg = _seq(_oid("1.2.840.10045.4.3.2"))
    name = _seq(_tlv(0x31, _seq(_oid("2.5.4.5"), _tlv(0x13, b"1"))))
    validity = _seq(quic._time(now - datetime.timedelta(hours=1)), quic._time(now + lifetime))
    exts = _tlv(0xA3, _seq(*extensions)) if extensions else b""
    tbs = _seq(_tlv(0xA0, quic._int(2)), quic._int(7), alg, name, validity, name, spki, exts)
    return _seq(tbs, alg, _tlv(0x03, b"\x00sig"))


class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.ident = Ed25519PrivateKey()
        self.spki = fake_spki()

    def test_roundtrip(self):
        der = build_certificate(self.ident, self.spki, lambda tbs: b"sig")
        self.assertEqual(verify_certificate(der).peer_id(), self.ident.peer_id())
        der2 = cert(self.spki, [signed_key_ext(self.ident, self.spki)])
        self.assertEqual(verify_certificate(der2).peer_id(), self.ident.peer_id())

    def test_rejects_expired_and_not_yet_valid(self):
        ext = [signed_key_ext(self.ident, self.spki)]
        with self.assertRaisesRegex(ValueError, "validity"):
            verify_certificate(cert(self.spki, ext, now=NOW - datetime.timedelta(days=800)))
        with self.assertRaisesRegex(ValueError, "validity"):
            verify_certificate(cert(self.spki, ext, now=NOW + datetime.timedelta(days=2)))

    def test_rejects_bad_extension_signature(self):
        sig = bytearray(self.ident.sign(quic.SIG_PREFIX + self.spki))
        sig[0] ^= 1
        der = cert(self.spki, [signed_key_ext(self.ident, self.spki, bytes(sig))])
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_certificate(der)

    def test_rejects_extension_signed_for_another_key(self):
        # the identity vouched for a different certificate key
        other_spki = fake_spki()
        der = cert(self.spki, [signed_key_ext(self.ident, other_spki)])
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_certificate(der)

    def test_rejects_missing_extension(self):
        with self.assertRaisesRegex(ValueError, "lacks"):
            verify_certificate(cert(self.spki, []))

    def test_unknown_critical_extension(self):
        unknown = _seq(_oid("1.2.3.4.5"), _tlv(0x01, b"\xff"), _tlv(0x04, b"\x05\x00"))
        with self.assertRaisesRegex(ValueError, "critical"):
            verify_certificate(cert(self.spki, [signed_key_ext(self.ident, self.spki), unknown]))
        # non-critical unknown extensions are ignored; a critical libp2p one is fine
        harmless = _seq(_oid("1.2.3.4.5"), _tlv(0x04, b"\x05\x00"))
        ok = cert(self.spki, [signed_key_ext(self.ident, self.spki, critical=True), harmless])
        self.assertEqual(verify_certificate(ok).peer_id(), self.ident.peer_id())

    def test_generated_certificate_is_valid_x509(self):
        if not quic.AVAILABLE:
            self.skipTest(f"QUIC unavailable: {quic.ERROR}")
        ctx = quic._context(self.ident)
        der = quic._i2d(quic._lib.i2d_X509, ctx.x509)
        self.assertEqual(quic._lib.X509_verify(ctx.x509, quic._lib.X509_get0_pubkey(ctx.x509)), 1)
        self.assertEqual(verify_certificate(der).peer_id(), self.ident.peer_id())


class TestAddressing(unittest.TestCase):
    def test_quic_target(self):
        self.assertEqual(quic.quic_target("/ip4/1.2.3.4/udp/4001/quic-v1/p2p/"
                                          "12D3KooWJgwhiomKUyAcqdDSq2PaMA6uM8QTAuDAuSofYfy4X6Qe"),
                         ("1.2.3.4", 4001))
        self.assertIsNone(quic.quic_target("/ip4/1.2.3.4/udp/4001/quic"))  # draft-29: unsupported
        self.assertIsNone(quic.quic_target("/ip4/1.2.3.4/udp/4001/quic-v1/webtransport"))
        self.assertIsNone(quic.quic_target("/ip4/1.2.3.4/tcp/4001"))

    def test_quic_preferred_when_available(self):
        addrs = ["/ip4/1.2.3.4/tcp/4001", "/ip4/1.2.3.4/udp/4001/quic-v1", "/ip4/10.0.0.1/tcp/4001"]
        order = [str(a) for a in _order_addrs(addrs)]
        if quic.AVAILABLE:
            self.assertEqual(order[0], "/ip4/1.2.3.4/udp/4001/quic-v1")
            self.assertTrue(dialable(Multiaddr(addrs[1])))
        else:
            self.assertNotIn("/ip4/1.2.3.4/udp/4001/quic-v1", order)
        self.assertEqual(order[-1], "/ip4/10.0.0.1/tcp/4001")


@unittest.skipUnless(os.environ.get("BASILISK_IPFS_NETWORK_TESTS") and quic.AVAILABLE,
                     "set BASILISK_IPFS_NETWORK_TESTS=1 (needs internet and OpenSSL QUIC)")
class TestQuicLive(unittest.TestCase):
    def test_dial_bootstrap_over_quic(self):
        from basilisk_ipfs import dns
        addrs = [a for a in dns.resolve_dnsaddr("/dnsaddr/bootstrap.libp2p.io") if quic.dialable(a)]
        self.assertTrue(addrs)
        with Host() as h:
            for a in addrs:
                try:
                    conn = h.connect(a)
                except Exception:
                    continue
                self.assertIn("quic-v1", str(conn.remote_addr))
                self.assertTrue(h.ping(conn.remote_peer, 2))
                info = h.identify(conn)
                self.assertIn("/ipfs/kad/1.0.0", info.protocols)
                return
            self.fail("no QUIC bootstrap peer reachable")

    def test_wrong_peer_id_rejected(self):
        from basilisk_ipfs import dns
        a = next(a for a in dns.resolve_dnsaddr("/dnsaddr/bootstrap.libp2p.io") if quic.dialable(a))
        wrong = Ed25519PrivateKey().peer_id()
        with self.assertRaises(OSError):
            quic.dial(Ed25519PrivateKey(), a.decapsulate_p2p()[0], wrong, timeout=8)


if __name__ == "__main__":
    unittest.main()
