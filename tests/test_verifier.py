import unittest

from modules import verifier
from modules.decoder import decode_token
from tests.helpers import TEST_SECRET, b64, crypto_available, make_token


class HmacTests(unittest.TestCase):
    def test_all_hs_algorithms_verify(self):
        for alg in ("HS256", "HS384", "HS512"):
            with self.subTest(alg=alg):
                r = verifier.verify_signature(decode_token(make_token(alg=alg)), TEST_SECRET)
                self.assertEqual(r.status, verifier.VERIFIED)

    def test_wrong_secret_fails(self):
        r = verifier.verify_signature(decode_token(make_token()), b"wrong" * 10)
        self.assertEqual(r.status, verifier.FAILED)

    def test_tampered_payload_fails(self):
        h, p, s = make_token().split(".")
        forged = "%s.%s.%s" % (h, b64(b'{"sub":"admin"}'), s)
        r = verifier.verify_signature(decode_token(forged), TEST_SECRET)
        self.assertEqual(r.status, verifier.FAILED)

    def test_no_key_is_not_verified(self):
        r = verifier.verify_signature(decode_token(make_token()))
        self.assertEqual(r.status, verifier.NOT_VERIFIED)
        self.assertFalse(r.verified)

    def test_empty_key_is_refused(self):
        r = verifier.verify_signature(decode_token(make_token(secret=b"")), b"")
        self.assertEqual(r.status, verifier.REJECTED)
        self.assertFalse(r.verified)

    def test_empty_signature_fails(self):
        r = verifier.verify_signature(decode_token(make_token(signature="")), TEST_SECRET)
        self.assertEqual(r.status, verifier.FAILED)

    def test_short_secret_flagged(self):
        r = verifier.verify_signature(decode_token(make_token(secret=b"short")), b"short")
        self.assertEqual(r.status, verifier.VERIFIED)
        self.assertTrue(r.details)


class UnsafeAlgorithmTests(unittest.TestCase):
    def test_none_never_valid(self):
        for name in ("none", "None", "NONE", " none "):
            with self.subTest(alg=name):
                t = make_token(header={"alg": name}, signature="")
                for key in (None, TEST_SECRET):
                    r = verifier.verify_signature(decode_token(t), key)
                    self.assertEqual(r.status, verifier.REJECTED)
                    self.assertFalse(r.verified)

    def test_missing_or_bad_alg_rejected(self):
        for header in ({}, {"alg": 5}, {"alg": ""}, {"alg": "HS1"}, {"alg": "RS999"}):
            with self.subTest(header=header):
                r = verifier.verify_signature(decode_token(make_token(header=header)), TEST_SECRET)
                self.assertEqual(r.status, verifier.REJECTED)

    def test_allowed_algorithm_pinning(self):
        r = verifier.verify_signature(decode_token(make_token(alg="HS512")), TEST_SECRET, ["HS256"])
        self.assertEqual(r.status, verifier.REJECTED)

    def test_algorithm_confusion_hmac_with_pem_rejected(self):
        pem = b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
        r = verifier.verify_signature(decode_token(make_token(secret=pem)), pem)
        self.assertEqual(r.status, verifier.REJECTED)
        self.assertIn("confusion", r.message.lower())

    def test_rsa_alg_with_plain_secret_rejected(self):
        t = make_token(header={"alg": "RS256"}, signature=b64(b"x"))
        r = verifier.verify_signature(decode_token(t), TEST_SECRET)
        self.assertEqual(r.status, verifier.REJECTED)

    def test_unsupported_known_alg_not_verified(self):
        t = make_token(header={"alg": "EdDSA"}, signature=b64(b"x"))
        self.assertEqual(verifier.verify_signature(decode_token(t), TEST_SECRET).status,
                         verifier.NOT_VERIFIED)


@unittest.skipUnless(crypto_available(), "cryptography not installed")
class AsymmetricTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec = {c: ec.generate_private_key(curve) for c, curve in
                  (("ES256", ec.SECP256R1()), ("ES384", ec.SECP384R1()), ("ES512", ec.SECP521R1()))}

    @staticmethod
    def pub_pem(private):
        from cryptography.hazmat.primitives import serialization
        return private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def sign_token(alg, sign_fn):
        import json
        h = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
        p = b64(b'{"sub":"u"}')
        sig = sign_fn(("%s.%s" % (h, p)).encode())
        return "%s.%s.%s" % (h, p, b64(sig))

    def test_rsa_and_pss(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        hs = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
        for alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
            h = hs[alg[2:]]
            pad = padding.PKCS1v15() if alg[0] == "R" else padding.PSS(padding.MGF1(h()), h().digest_size)
            tok = self.sign_token(alg, lambda d: self.rsa_key.sign(d, pad, h()))
            with self.subTest(alg=alg):
                r = verifier.verify_signature(decode_token(tok), self.pub_pem(self.rsa_key))
                self.assertEqual(r.status, verifier.VERIFIED, r.message)

    def test_rsa_wrong_key_fails(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        tok = self.sign_token("RS256", lambda d: self.rsa_key.sign(d, padding.PKCS1v15(), hashes.SHA256()))
        r = verifier.verify_signature(decode_token(tok), self.pub_pem(other))
        self.assertEqual(r.status, verifier.FAILED)

    def test_ecdsa(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        hs = {"ES256": (hashes.SHA256, 32), "ES384": (hashes.SHA384, 48), "ES512": (hashes.SHA512, 66)}
        for alg, (h, n) in hs.items():
            def sign(d, alg=alg, h=h, n=n):
                r, s = decode_dss_signature(self.ec[alg].sign(d, ec.ECDSA(h())))
                return r.to_bytes(n, "big") + s.to_bytes(n, "big")
            tok = self.sign_token(alg, sign)
            with self.subTest(alg=alg):
                res = verifier.verify_signature(decode_token(tok), self.pub_pem(self.ec[alg]))
                self.assertEqual(res.status, verifier.VERIFIED, res.message)

    def test_ec_curve_mismatch_rejected(self):
        tok = self.sign_token("ES256", lambda d: b"\x01" * 64)
        r = verifier.verify_signature(decode_token(tok), self.pub_pem(self.ec["ES384"]))
        self.assertEqual(r.status, verifier.REJECTED)

    def test_key_type_mismatch_rejected(self):
        tok = self.sign_token("RS256", lambda d: b"\x01" * 256)
        r = verifier.verify_signature(decode_token(tok), self.pub_pem(self.ec["ES256"]))
        self.assertEqual(r.status, verifier.REJECTED)


if __name__ == "__main__":
    unittest.main()
