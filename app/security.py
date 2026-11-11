"""口令、令牌与签名。"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid

JWT_SECRET = os.environ.get("AUTHKIT_JWT_SECRET", "authkit-dev-secret")
ISSUER = os.environ.get("AUTHKIT_ISSUER", "https://authkit.local")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()
    return f"pbkdf2${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, digest)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_access_token(user_id: int, client_id: str, ttl: int = 900) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "cid": client_id,
        "iss": ISSUER,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    head = _b64e(json.dumps(header, separators=(",", ":")).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def verify_access_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(_b64d(parts[0]))
    payload = json.loads(_b64d(parts[1]))
    if header.get("alg") != "HS256":
        raise ValueError("unsupported alg")
    expected = _b64e(hmac.new(JWT_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise ValueError("bad signature")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired")
    return payload


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)


def new_reset_token() -> str:
    return uuid.uuid1().hex
