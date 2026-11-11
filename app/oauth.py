"""OAuth2 授权码流程（RFC 6749 + RFC 7636 + RFC 9700）。"""

import hmac
import time

from app import security, store


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "") -> None:
        super().__init__(error)
        self.error = error
        self.description = description


def client_redirect_uris(client) -> list[str]:
    return [u.strip() for u in str(client["redirect_uris"]).split(",") if u.strip()]


def _validate_redirect_uri(client, redirect_uri: str) -> None:
    """RFC 6749 §3.1.2.3 / §4.1.3：redirect_uri 必须与注册值精确匹配。"""
    if redirect_uri not in client_redirect_uris(client):
        raise OAuthError("invalid_request", "unregistered redirect_uri")


def _validate_pkce_request(code_challenge: str | None,
                           code_challenge_method: str | None) -> str | None:
    """授权端点的 PKCE 参数校验（RFC 7636 §4.3、§4.4.1）。"""
    if code_challenge is None:
        if code_challenge_method is not None:
            raise OAuthError("invalid_request", "code_challenge_method requires code_challenge")
        return None
    if not security.is_valid_pkce_challenge(code_challenge):
        raise OAuthError("invalid_request", "malformed code_challenge")
    # RFC 7636 §4.3：缺省时按 plain 处理；§4.4.1：仅允许 S256 / plain
    method = code_challenge_method or "plain"
    if method not in ("S256", "plain"):
        raise OAuthError(
            "invalid_request", f"unsupported code_challenge_method: {method}"
        )
    return method


def issue_authorization_code(client_id: str, user_id: int, redirect_uri: str,
                             code_challenge: str | None,
                             code_challenge_method: str | None) -> str:
    client = store.get_client(client_id)
    if client is None:
        raise OAuthError("invalid_client", "unknown client")
    _validate_redirect_uri(client, redirect_uri)
    method = _validate_pkce_request(code_challenge, code_challenge_method)

    code = security.new_opaque_token()
    store.save_auth_code(code, client_id, user_id, redirect_uri, code_challenge, method)
    return code


def _check_pkce(stored_challenge: str | None, method: str | None,
                verifier: str | None) -> None:
    """令牌端点的 PKCE 校验（RFC 7636 §4.6）。"""
    if stored_challenge is None:
        # 授权时未带 challenge：PKCE 对该客户端为可选，不强制
        return
    if not verifier or not security.is_valid_pkce_verifier(verifier):
        raise OAuthError("invalid_grant", "valid code_verifier required")
    if method == "S256":
        computed = security.s256_challenge(verifier)
    else:
        computed = verifier
    if not hmac.compare_digest(computed, stored_challenge):
        raise OAuthError("invalid_grant", "code_verifier mismatch")


def exchange_code(client_id: str, client_secret: str, code: str,
                  redirect_uri: str, code_verifier: str | None) -> dict:
    client = store.get_client(client_id)
    if client is None or not hmac.compare_digest(client["client_secret"], client_secret):
        raise OAuthError("invalid_client", "bad client credentials")

    row = store.get_auth_code(code)
    if row is None:
        raise OAuthError("invalid_grant", "unknown code")
    if int(row["expires_at"]) < int(time.time()):
        raise OAuthError("invalid_grant", "code expired")
    if row["client_id"] != client_id:
        raise OAuthError("invalid_grant", "code was issued to another client")
    # RFC 6749 §4.1.3：令牌请求中的 redirect_uri 必须与授权时完全一致
    if row["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri mismatch")
    _validate_redirect_uri(client, redirect_uri)
    # 以上全部校验通过后再做 PKCE（RFC 7636 §4.6）
    _check_pkce(row["code_challenge"], row["code_challenge_method"], code_verifier)

    # 原子认领；重放的 code 会返回 replay=True
    row, replay = store.claim_auth_code(code)
    if replay:
        # RFC 6749 §4.1.2 + RFC 9700 §3.6.1：code 一次性，重放即吊销整个授权家族
        store.revoke_refresh_family(code)
        raise OAuthError("invalid_grant", "authorization code already used")

    access_token = security.create_access_token(int(row["user_id"]), client_id)
    refresh_token = security.new_opaque_token()
    # 以授权码本身作为令牌家族标识，重放时可一次性吊销本次授权的全部 refresh token
    store.save_refresh_token(refresh_token, client_id, int(row["user_id"]), family=code)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": refresh_token,
    }


def refresh(client_id: str, client_secret: str, refresh_token: str) -> dict:
    client = store.get_client(client_id)
    if client is None or not hmac.compare_digest(client["client_secret"], client_secret):
        raise OAuthError("invalid_client", "bad client credentials")

    row = store.get_refresh_token(refresh_token)
    if row is None:
        raise OAuthError("invalid_grant", "unknown refresh token")
    if int(row["expires_at"]) < int(time.time()):
        raise OAuthError("invalid_grant", "refresh token expired")
    # RFC 6749 §10.4：refresh token 与客户端身份绑定
    if row["client_id"] != client_id:
        raise OAuthError("invalid_grant", "refresh token issued to another client")
    if int(row["revoked"]) == 1:
        # RFC 9700 §3.3.1：重放已轮换/吊销的令牌 → 吊销整个令牌家族
        store.revoke_refresh_family(row["family"])
        raise OAuthError("invalid_grant", "refresh token revoked or replayed")

    new_refresh_token = security.new_opaque_token()
    store.rotate_refresh_token(refresh_token, new_refresh_token)

    access_token = security.create_access_token(int(row["user_id"]), client_id)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": new_refresh_token,
    }
