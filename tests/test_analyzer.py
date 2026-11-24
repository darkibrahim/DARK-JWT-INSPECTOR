import time
import unittest
from datetime import datetime, timezone

from modules import analyzer, security, verifier
from modules.decoder import decode_token
from tests.helpers import make_token

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
T = int(NOW.timestamp())


def times(payload, leeway=0):
    return analyzer.analyze_time(payload, now=NOW, leeway=leeway)


def findings_for(token, verification=None):
    d = decode_token(token)
    return security.evaluate(d, analyzer.analyze_header(d.header), analyzer.analyze_time(d.payload),
                             verification)


def codes(findings):
    return {f["code"] for f in findings}


class TimeTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(times({"iat": T - 10, "exp": T + 100})["state"], "valid")

    def test_expired(self):
        t = times({"exp": T - 5})
        self.assertEqual(t["state"], "expired")
        self.assertIn("ago", t["exp"]["relative"])

    def test_leeway_saves_recently_expired(self):
        self.assertEqual(times({"exp": T - 5}, leeway=30)["state"], "valid")

    def test_not_yet_valid(self):
        self.assertEqual(times({"nbf": T + 500, "exp": T + 900})["state"], "not_yet_valid")

    def test_no_expiration(self):
        self.assertEqual(times({"sub": "a"})["state"], "no_expiration")

    def test_invalid_types_and_ranges(self):
        for bad in ("123", True, None, [1], 1e400, 10 ** 400, 10 ** 20, float("nan")):
            with self.subTest(bad=bad):
                self.assertEqual(times({"exp": bad})["state"], "invalid")

    def test_lifetime_and_age(self):
        t = times({"iat": T - 60, "exp": T + 3540})
        self.assertEqual(t["lifetime_seconds"], 3600)
        self.assertEqual(t["age_seconds"], 60)

    def test_humanize(self):
        self.assertEqual(analyzer.humanize_seconds(90061), "1d 1h 1m")
        self.assertEqual(analyzer.humanize_seconds(0), "0s")


class AlgorithmTests(unittest.TestCase):
    def test_inspect(self):
        self.assertTrue(analyzer.inspect_algorithm("HS256")["safe"])
        self.assertFalse(analyzer.inspect_algorithm("none")["safe"])
        self.assertFalse(analyzer.inspect_algorithm(None)["known"])
        self.assertFalse(analyzer.inspect_algorithm("XX1")["known"])

    def test_payload_analysis(self):
        p = analyzer.analyze_payload({"iss": "x", "aud": ["a", "b"], "role": "admin"})
        self.assertEqual(p["audiences"], ["a", "b"])
        self.assertEqual(p["custom_claims"], ["role"])
        self.assertIn("exp", p["missing_registered"])


class SecurityFindingTests(unittest.TestCase):
    def test_none_critical(self):
        f = findings_for(make_token(header={"alg": "none"}, signature=""))
        self.assertIn("ALG_NONE", codes(f))
        self.assertEqual(f[0]["severity"], "CRITICAL")

    def test_header_key_sources_and_kid(self):
        t = make_token(header={"alg": "HS256", "jku": "http://x", "kid": "../../etc/passwd"})
        c = codes(findings_for(t))
        self.assertIn("HEADER_KEY_SOURCE_JKU", c)
        self.assertIn("KID_SUSPICIOUS", c)

    def test_clean_kid_not_flagged(self):
        self.assertNotIn("KID_SUSPICIOUS", codes(findings_for(make_token(header={"alg": "HS256", "kid": "key-2026-01"}))))

    def test_missing_exp_and_long_lifetime(self):
        self.assertIn("NO_EXPIRATION", codes(findings_for(make_token({"sub": "a"}))))
        now = int(time.time())
        c = codes(findings_for(make_token({"iat": now, "exp": now + 90 * 86400, "iss": "i", "aud": "a"})))
        self.assertIn("LONG_LIFETIME", c)

    def test_sensitive_payload(self):
        self.assertIn("SENSITIVE_PAYLOAD", codes(findings_for(make_token({"password": "x", "exp": 9999999999}))))

    def test_standard_claims_not_sensitive(self):
        self.assertNotIn("SENSITIVE_PAYLOAD", codes(findings_for(make_token({"auth_time": 1, "exp": 9999999999}))))

    def test_not_verified_notice(self):
        d = decode_token(make_token())
        v = verifier.verify_signature(d)
        f = security.evaluate(d, analyzer.analyze_header(d.header), analyzer.analyze_time(d.payload), v)
        self.assertIn("NOT_VERIFIED", codes(f))

    def test_sensitive_key_matches_words_not_substrings(self):
        for name in ("password", "user_password", "apiKey", "api_key", "clientSecret", "phoneNumber",
                     "email", "home_address", "card_number", "ssn", "otp", "privateKey", "accesstoken"):
            with self.subTest(name=name):
                self.assertTrue(security.is_sensitive_key(name))
        for name in ("footprint", "adobe", "discard", "cardinal", "scope", "role", "roles",
                     "auth_time", "iss", "sub", "department", "tenant_id"):
            with self.subTest(name=name):
                self.assertFalse(security.is_sensitive_key(name))

    def test_empty_signature_flagged(self):
        self.assertIn("SIGNATURE_EMPTY", codes(findings_for(make_token(signature=""))))


if __name__ == "__main__":
    unittest.main()
