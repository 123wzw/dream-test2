"""AuthKit HTTP 接口。"""

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app import oauth, security, store

app = FastAPI(title="AuthKit", version="0.7.2")

store.init_db()


class LoginIn(BaseModel):
    email: str
    password: str


class TokenIn(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None


class ResetRequestIn(BaseModel):
    email: str


class ResetConfirmIn(BaseModel):
    token: str
    new_password: str


def current_user(request: Request) -> dict:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = header.split(" ", 1)[1].strip()
    try:
        payload = security.verify_access_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    user = store.get_user(int(payload["sub"]))
    if user is None:
        raise HTTPException(status_code=401, detail="unknown subject")
    return dict(user)


@app.post("/auth/login")
def login(payload: LoginIn):
    user = store.get_user_by_email(payload.email)
    if user is None or not security.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {
        "access_token": security.create_access_token(int(user["id"]), "authkit-web"),
        "token_type": "Bearer",
        "user": {"id": user["id"], "email": user["email"], "display_name": user["display_name"]},
    }


@app.get("/oauth/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str = "",
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported response_type")

    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="login required")
    try:
        payload = security.verify_access_token(header.split(" ", 1)[1].strip())
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None

    try:
        code = oauth.issue_authorization_code(
            client_id, int(payload["sub"]), redirect_uri, code_challenge, code_challenge_method
        )
    except oauth.OAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.error) from None

    separator = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{separator}code={code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(url=location, status_code=302)


@app.post("/oauth/token")
def token(payload: TokenIn):
    try:
        if payload.grant_type == "authorization_code":
            if not payload.code or not payload.redirect_uri:
                raise HTTPException(status_code=400, detail="code and redirect_uri required")
            return oauth.exchange_code(
                payload.client_id, payload.client_secret, payload.code,
                payload.redirect_uri, payload.code_verifier,
            )
        if payload.grant_type == "refresh_token":
            if not payload.refresh_token:
                raise HTTPException(status_code=400, detail="refresh_token required")
            return oauth.refresh(payload.client_id, payload.client_secret, payload.refresh_token)
    except oauth.OAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.error) from None
    raise HTTPException(status_code=400, detail="unsupported grant_type")


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "display_name": user["display_name"]}


@app.post("/auth/password-reset/request")
def request_reset(payload: ResetRequestIn):
    user = store.get_user_by_email(payload.email)
    if user is not None:
        token = security.new_reset_token()
        store.save_reset_token(token, int(user["id"]))
        print(f"[password-reset] {user['email']} -> {token}")
    return {"status": "sent"}


@app.post("/auth/password-reset/confirm")
def confirm_reset(payload: ResetConfirmIn):
    row = store.get_reset_token(payload.token)
    if row is None:
        raise HTTPException(status_code=400, detail="invalid token")
    import time as _time

    if int(row["expires_at"]) < int(_time.time()):
        raise HTTPException(status_code=400, detail="token expired")
    store.update_password(int(row["user_id"]), security.hash_password(payload.new_password))
    return {"status": "password updated"}
