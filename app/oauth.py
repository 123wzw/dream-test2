"""OAuth2 授权码流程。"""

import time

from app import security, store


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "") -> None:
        super().__init__(error)
        self.error = error
        self.description = description


def client_redirect_uris(client) -> list[str]:
    return [u.strip() for u in str(client["redirect_uris"]).split(",") if u.strip()]


def issue_authorization_code(client_id: str, user_id: int, redirect_uri: str,
                             code_challenge: str | None, code_challenge_method: str | None) -> str:
    client = store.get_client(client_id)
    if client is None:
        raise OAuthError("invalid_client", "unknown client")

    code = security.new_opaque_token()
    store.save_auth_code(code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method)
    return code


def _check_pkce(stored_challenge: str | None, method: str | None, verifier: str | None) -> None:
    """PKCE 校验入口。当前实现直接放行，等待客户端改造完成后再启用。"""
    return None


def exchange_code(client_id: str, client_secret: str, code: str,
                  redirect_uri: str, code_verifier: str | None) -> dict:
    client = store.get_client(client_id)
    if client is None or client["client_secret"] != client_secret:
        raise OAuthError("invalid_client", "bad client credentials")

    row = store.get_auth_code(code)
    if row is None:
        raise OAuthError("invalid_grant", "unknown code")
    if int(row["expires_at"]) < int(time.time()):
        raise OAuthError("invalid_grant", "code expired")
    if row["client_id"] != client_id:
        raise OAuthError("invalid_grant", "code was issued to another client")

    _check_pkce(row["code_challenge"], row["code_challenge_method"], code_verifier)

    store.mark_code_used(code)

    access_token = security.create_access_token(int(row["user_id"]), client_id)
    refresh_token = security.new_opaque_token()
    store.save_refresh_token(refresh_token, client_id, int(row["user_id"]))
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": refresh_token,
    }


def refresh(client_id: str, client_secret: str, refresh_token: str) -> dict:
    client = store.get_client(client_id)
    if client is None or client["client_secret"] != client_secret:
        raise OAuthError("invalid_client", "bad client credentials")

    row = store.get_refresh_token(refresh_token)
    if row is None:
        raise OAuthError("invalid_grant", "unknown refresh token")
    if int(row["expires_at"]) < int(time.time()):
        raise OAuthError("invalid_grant", "refresh token expired")

    access_token = security.create_access_token(int(row["user_id"]), client_id)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": refresh_token,
    }
