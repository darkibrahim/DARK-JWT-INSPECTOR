import unittest

from modules.decoder import JWTDecodeError, b64url_decode, decode_token
from tests.helpers import b64, make_token


class DecoderTests(unittest.TestCase):
    def test_valid_token(self):
        d = decode_token(make_token({"sub": "a", "n": 1}))
        self.assertEqual(d.header["alg"], "HS256")
        self.assertEqual(d.payload, {"sub": "a", "n": 1})
        self.assertTrue(d.signature)

    def test_bearer_and_quotes_stripped(self):
        t = make_token()
        self.assertEqual(decode_token("Bearer " + t).token, t)
        self.assertEqual(decode_token('"%s"' % t).token, t)

    def test_unsigned_token_empty_signature(self):
        t = make_token(header={"alg": "none"}, signature="")
        d = decode_token(t)
        self.assertEqual(d.signature, b"")

    def test_unicode_payload(self):
        self.assertEqual(decode_token(make_token({"name": "ইব্রাহিম"})).payload["name"], "ইব্রাহিম")

    def test_malformed_inputs(self):
        good = make_token()
        h, p, s = good.split(".")
        bad = [
            "", "   ", "abc", "a.b", "a.b.c.d", "a.b.c.d.e.f",
            "%s.%s" % (h, p), ".%s.%s" % (p, s), "%s..%s" % (h, s),
            "%s.%s.%s" % ("!!!", p, s), "%s.%s.%s" % (h, p, "@@"),
            "%s.%s.%s" % (b64(b"notjson"), p, s),
            "%s.%s.%s" % (h, b64(b"[1,2]"), s),
            "%s.%s.%s" % (b64(b"\xff\xfe"), p, s),
            good + " extra", "A" * 70000,
        ]
        for token in bad:
            with self.subTest(token=token[:30]):
                with self.assertRaises(JWTDecodeError):
                    decode_token(token)

    def test_non_string_rejected(self):
        for value in (None, 5, b"abc", ["a"]):
            with self.assertRaises(JWTDecodeError):
                decode_token(value)

    def test_jwe_detected(self):
        with self.assertRaises(JWTDecodeError) as ctx:
            decode_token("a.b.c.d.e")
        self.assertIn("JWE", str(ctx.exception))

    def test_duplicate_keys_reported(self):
        h = b64(b'{"alg":"HS256"}')
        p = b64(b'{"sub":"a","sub":"b"}')
        d = decode_token("%s.%s.%s" % (h, p, b64(b"x")))
        self.assertEqual(d.duplicate_keys, ["sub"])

    def test_b64url_padding_optional(self):
        self.assertEqual(b64url_decode("YQ"), b"a")
        self.assertEqual(b64url_decode("YQ=="), b"a")
        with self.assertRaises(JWTDecodeError):
            b64url_decode("Y")


if __name__ == "__main__":
    unittest.main()
