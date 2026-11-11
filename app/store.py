"""SQLite 存储层。"""

import os
import sqlite3
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def db_path() -> str:
    return os.environ.get("AUTHKIT_DB", str(BASE_DIR / "authkit.db"))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    from app.security import hash_password

    conn = connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_secret TEXT NOT NULL,
                name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT,
                code_challenge_method TEXT,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                family TEXT NOT NULL DEFAULT '',
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS reset_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            """
        )
        # 轻量迁移：为旧库补齐刷新令牌轮换/吊销所需列（新库建表时已包含）
        existing = {r[1] for r in conn.execute("PRAGMA table_info(refresh_tokens)")}
        if "family" not in existing:
            conn.execute("ALTER TABLE refresh_tokens ADD COLUMN family TEXT NOT NULL DEFAULT ''")
        if "revoked" not in existing:
            conn.execute("ALTER TABLE refresh_tokens ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0")
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)",
                ("alice@example.com", hash_password("alice-pass"), "Alice"),
            )
            conn.execute(
                "INSERT INTO clients (client_id, client_secret, name, redirect_uris) VALUES (?, ?, ?, ?)",
                ("demo-web", "demo-secret", "Demo Web", "http://localhost:3000/callback"),
            )
            conn.commit()
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


def get_user(user_id: int):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


def get_client(client_id: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    finally:
        conn.close()


def save_auth_code(code: str, client_id: str, user_id: int, redirect_uri: str,
                   code_challenge: str | None, code_challenge_method: str | None) -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, code_challenge,"
            " code_challenge_method, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method,
             int(time.time()) + 300),
        )
        conn.commit()
    finally:
        conn.close()


def get_auth_code(code: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM auth_codes WHERE code = ?", (code,)).fetchone()
    finally:
        conn.close()


def claim_auth_code(code: str):
    """原子地认领授权码：仅当 code 存在且未使用时标记为已使用。

    返回 (row, replay)：
    - row 为 None 表示 code 不存在；
    - replay 为 True 表示 code 已被使用过（重放攻击），row 仍返回原始记录，
      供调用方吊销该授权派生出的整个令牌家族。
    """
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM auth_codes WHERE code = ?", (code,)).fetchone()
        if row is None:
            return None, False
        if int(row["used"]) == 1:
            return row, True
        conn.execute("UPDATE auth_codes SET used = 1 WHERE code = ? AND used = 0", (code,))
        conn.commit()
        return row, False
    finally:
        conn.close()


def save_refresh_token(token: str, client_id: str, user_id: int, family: str) -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO refresh_tokens (token, client_id, user_id, expires_at, family, revoked)"
            " VALUES (?, ?, ?, ?, ?, 0)",
            (token, client_id, user_id, int(time.time()) + 86400 * 30, family),
        )
        conn.commit()
    finally:
        conn.close()


def rotate_refresh_token(old_token: str, new_token: str) -> None:
    """原子轮换：吊销旧 refresh token，并在同一家族内签发新令牌。"""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token = ?", (old_token,)
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (old_token,)
        )
        conn.execute(
            "INSERT INTO refresh_tokens (token, client_id, user_id, expires_at, family, revoked)"
            " VALUES (?, ?, ?, ?, ?, 0)",
            (new_token, row["client_id"], row["user_id"],
             int(time.time()) + 86400 * 30, row["family"]),
        )
        conn.commit()
    finally:
        conn.close()


def revoke_refresh_family(family: str) -> None:
    """吊销同一次授权（令牌家族）派生出的全部 refresh token。"""
    conn = connect()
    try:
        conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE family = ?", (family,)
        )
        conn.commit()
    finally:
        conn.close()


def get_refresh_token(token: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM refresh_tokens WHERE token = ?", (token,)).fetchone()
    finally:
        conn.close()


def save_reset_token(token: str, user_id: int) -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, int(time.time()) + 900),
        )
        conn.commit()
    finally:
        conn.close()


def get_reset_token(token: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
    finally:
        conn.close()


def update_password(user_id: int, password_hash: str) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()
    finally:
        conn.close()
