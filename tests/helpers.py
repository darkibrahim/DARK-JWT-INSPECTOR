"""Locally generated, throw-away test tokens. No real secrets are used."""
import base64
import hashlib
import hmac
import json
import time

TEST_SECRET = b"unit-test-secret-" * 4  # 68 bytes, test only


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(payload=None, header=None, secret=TEST_SECRET, alg="HS256", signature=None):
    header = header if header is not None else {"alg": alg, "typ": "JWT"}
    if payload is None:
        now = int(time.time())
        payload = {"sub": "user1", "iss": "test", "aud": "app", "iat": now, "exp": now + 3600}
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = ("%s.%s" % (h, p)).encode()
    if signature is None:
        digest = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}[alg[2:]]
        signature = b64(hmac.new(secret, signing_input, digest).digest())
    return "%s.%s.%s" % (h, p, signature)


def crypto_available():
    try:
        import cryptography  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: F401
        return True
    except Exception:
        return False
