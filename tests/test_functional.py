"""AuthKit 功能回归测试。"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="authkit-test-")
os.environ["AUTHKIT_DB"] = os.path.join(_TMP, "authkit.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app, follow_redirects=False)

CLIENT_ID = "demo-web"
CLIENT_SECRET = "demo-secret"
REDIRECT = "http://localhost:3000/callback"


def _login(email="alice@example.com", password="alice-pass") -> str:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _authorize(token: str, redirect_uri: str = REDIRECT) -> str:
    resp = client.get(
        "/oauth/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "xyz",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 302, resp.text
    return resp.headers["location"]


def _exchange(code: str, redirect_uri: str = REDIRECT) -> dict:
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_login_success():
    assert _login()


def test_login_wrong_password():
    resp = client.post("/auth/login", json={"email": "alice@example.com", "password": "bad"})
    assert resp.status_code == 401


def test_authorize_redirects_with_code():
    location = _authorize(_login())
    assert "code=" in location and location.startswith(REDIRECT)


def test_full_authorization_code_flow():
    location = _authorize(_login())
    code = location.split("code=")[1].split("&")[0]
    tokens = _exchange(code)
    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"] and tokens["refresh_token"]


def test_api_me_with_access_token():
    location = _authorize(_login())
    code = location.split("code=")[1].split("&")[0]
    tokens = _exchange(code)
    resp = client.get("/api/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "alice@example.com"


def test_api_me_requires_token():
    assert client.get("/api/me").status_code == 401


def test_refresh_token_issues_new_access_token():
    location = _authorize(_login())
    code = location.split("code=")[1].split("&")[0]
    tokens = _exchange(code)
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_token_rejects_bad_client_secret():
    location = _authorize(_login())
    code = location.split("code=")[1].split("&")[0]
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": "wrong",
            "code": code,
            "redirect_uri": REDIRECT,
        },
    )
    assert resp.status_code == 400


def test_password_reset_flow():
    token = _login()
    assert token
    resp = client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    assert resp.status_code == 200

    from app import store

    conn = store.connect()
    row = conn.execute("SELECT * FROM reset_tokens ORDER BY rowid DESC LIMIT 1").fetchone()
    conn.close()
    assert row is not None

    resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": row["token"], "new_password": "new-alice-pass"},
    )
    assert resp.status_code == 200
    assert _login(password="new-alice-pass")
