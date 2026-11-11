"""OAuth2 授权流程安全回归测试（对照 RFC 6749 / RFC 7636 / RFC 9700）。

每个 test_*_attack_* 都是一个可复现的攻击：
修复前必须失败（攻击得手），修复后必须通过（攻击被拦截）。
test_pkce_s256_happy_path 是正向用例，保证加固不会误伤合法 PKCE 客户端。
"""

import tempfile

import pytest

from fastapi.testclient import TestClient  # noqa: E402

from app import store  # noqa: E402
from app.main import app  # noqa: E402

# 独立于功能测试的库路径；通过 autouse fixture 在每个用例前注入并初始化，
# 避免依赖 AUTHKIT_DB 全局变量与模块导入顺序（功能测试会改写 alice 的口令）。
_SECURITY_DB = tempfile.mktemp(prefix="authkit-security-", suffix=".db")


@pytest.fixture(autouse=True)
def _isolated_database(monkeypatch):
    monkeypatch.setenv("AUTHKIT_DB", _SECURITY_DB)
    store.init_db()
    yield


store.init_db()
client = TestClient(app, follow_redirects=False)

CLIENT_ID = "demo-web"
CLIENT_SECRET = "demo-secret"
REDIRECT = "http://localhost:3000/callback"
EVIL_REDIRECT = "http://evil.example.com/callback"

# RFC 7636 附录 B 的标准 S256 测试向量
RFC7636_VERIFIER = (
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _login() -> str:
    resp = client.post(
        "/auth/login", json={"email": "alice@example.com", "password": "alice-pass"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _authorize_raw(token: str, *, client_id=CLIENT_ID, redirect_uri=REDIRECT,
                   state="xyz", code_challenge=None, code_challenge_method=None):
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
    if code_challenge_method is not None:
        params["code_challenge_method"] = code_challenge_method
    return client.get(
        "/oauth/authorize", params=params, headers={"Authorization": f"Bearer {token}"}
    )


def _extract_code(location: str) -> str:
    return location.split("code=")[1].split("&")[0]


def _exchange_raw(*, code, redirect_uri=REDIRECT, client_id=CLIENT_ID,
                  client_secret=CLIENT_SECRET, code_verifier=None):
    body = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if code_verifier is not None:
        body["code_verifier"] = code_verifier
    return client.post("/oauth/token", json=body)


def _pkce_code(verifier: str, method: str = "S256") -> str:
    resp = _authorize_raw(
        _login(),
        code_challenge=RFC7636_CHALLENGE if method == "S256" else verifier,
        code_challenge_method=method,
    )
    assert resp.status_code == 302, resp.text
    return _extract_code(resp.headers["location"])


def _make_second_client() -> tuple[str, str]:
    conn = store.connect()
    try:
        conn.execute(
            "INSERT INTO clients (client_id, client_secret, name, redirect_uris)"
            " VALUES (?, ?, ?, ?)",
            ("other-app", "other-secret", "Other App", "http://localhost:4000/cb"),
        )
        conn.commit()
    finally:
        conn.close()
    return "other-app", "other-secret"


# --- V1：authorize 端未注册 redirect_uri（开放重定向 / 授权码外带）-------------

def test_attack_authorize_rejects_unregistered_redirect_uri():
    resp = _authorize_raw(_login(), redirect_uri=EVIL_REDIRECT)
    # 修复前：302 跳转到攻击者站点并把 code 带出去；修复后：必须拒绝
    assert resp.status_code == 400, resp.text
    assert "evil.example.com" not in resp.headers.get("location", "")


# --- V2：token 端 redirect_uri 与授权时不一致（绕过授权端点校验）---------------

def test_attack_token_rejects_mismatched_redirect_uri():
    location = _authorize_raw(_login(), redirect_uri=REDIRECT).headers["location"]
    code = _extract_code(location)
    resp = _exchange_raw(code=code, redirect_uri=EVIL_REDIRECT)
    # 修复前：换发 access_token；修复后：invalid_grant / invalid_request
    assert resp.status_code == 400, resp.text


# --- V3：授权码可重放 ---------------------------------------------------------

def test_attack_authorization_code_is_single_use():
    location = _authorize_raw(_login()).headers["location"]
    code = _extract_code(location)
    first = _exchange_raw(code=code)
    assert first.status_code == 200, first.text
    # 修复前：同一个 code 第二次仍换出令牌；修复后：必须拒绝
    second = _exchange_raw(code=code)
    assert second.status_code == 400, second.text


def test_attack_replayed_code_revokes_refresh_token_family():
    location = _authorize_raw(_login()).headers["location"]
    code = _extract_code(location)
    tokens = _exchange_raw(code=code).json()
    refresh_token = tokens["refresh_token"]
    # 攻击者拿到 code 后重放：按 RFC 9700 §3.6.1 必须吊销该授权派生的全部令牌
    _exchange_raw(code=code)
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
        },
    )
    assert resp.status_code == 400, resp.text


# --- V4：PKCE 完全未生效（_check_pkce 直接放行）-------------------------------

def test_attack_pkce_verifier_required_when_challenge_present():
    code = _pkce_code(RFC7636_VERIFIER)
    # 修复前：不带 code_verifier 也能换令牌；修复后：invalid_grant
    resp = _exchange_raw(code=code)
    assert resp.status_code == 400, resp.text


def test_attack_pkce_wrong_verifier_rejected():
    code = _pkce_code(RFC7636_VERIFIER)
    resp = _exchange_raw(code=code, code_verifier="A" * 64)
    assert resp.status_code == 400, resp.text


def test_pkce_s256_happy_path():
    """正向对照：合法 S256 流程在修复前后都必须成功。"""
    code = _pkce_code(RFC7636_VERIFIER)
    resp = _exchange_raw(code=code, code_verifier=RFC7636_VERIFIER)
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"]


def test_attack_authorize_rejects_unknown_challenge_method():
    resp = _authorize_raw(
        _login(),
        code_challenge=RFC7636_CHALLENGE,
        code_challenge_method="MD5",
    )
    assert resp.status_code == 400, resp.text


# --- V5：refresh token 不轮换、可无限次重放 -----------------------------------

def test_attack_refresh_token_rotates_on_use():
    location = _authorize_raw(_login()).headers["location"]
    code = _extract_code(location)
    old = _exchange_raw(code=code).json()["refresh_token"]
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": old,
        },
    )
    assert resp.status_code == 200, resp.text
    new = resp.json()["refresh_token"]
    assert new and new != old
    # 修复前：旧 refresh token 仍可再次使用；修复后：已失效
    replay = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": old,
        },
    )
    assert replay.status_code == 400, replay.text


def test_attack_refresh_token_reuse_revokes_entire_family():
    location = _authorize_raw(_login()).headers["location"]
    code = _extract_code(location)
    original = _exchange_raw(code=code).json()["refresh_token"]

    # 合法客户端正常轮换一次
    rotated = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": original,
        },
    ).json()["refresh_token"]

    # 攻击者重放已轮换掉的旧令牌：按 RFC 9700 §3.3.1 必须吊销整个令牌家族
    client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": original,
        },
    )

    # 连合法的新令牌也必须一起失效
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": rotated,
        },
    )
    assert resp.status_code == 400, resp.text


def test_attack_refresh_token_rejected_for_other_client():
    other_id, other_secret = _make_second_client()
    location = _authorize_raw(_login()).headers["location"]
    code = _extract_code(location)
    refresh_token = _exchange_raw(code=code).json()["refresh_token"]
    # RFC 6749 §10.4：refresh token 与客户端身份绑定，禁止跨客户端使用
    resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": other_id,
            "client_secret": other_secret,
            "refresh_token": refresh_token,
        },
    )
    assert resp.status_code == 400, resp.text
