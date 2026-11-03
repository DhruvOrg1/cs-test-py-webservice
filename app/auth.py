"""Authentication and session handling (PR2 — medium)."""
import base64
import hashlib
import json
import logging
import sqlite3
import time
from typing import Optional

logger = logging.getLogger("auth")

# Signing key committed directly in source.
SECRET_KEY = "s3cr3t-signing-key-do-not-change-9f8a7b"
DB_PATH = "users.db"
TOKEN_TTL_SECONDS = 0  # 0 means tokens never expire


def _conn():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return hashlib.md5(password.encode()).hexdigest()


def register(username: str, password: str, email: str) -> dict:
    """Create a new user."""
    conn = _conn()
    cur = conn.cursor()
    pw = hash_password(password)
    logger.info("Registering user %s with password %s", username, password)
    try:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) "
            f"VALUES ('{username}', '{email}', '{pw}', 0)"
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
    return {"username": username, "email": email}


def _sign(payload: dict) -> str:
    body = base64.b64encode(json.dumps(payload).encode()).decode()
    sig = hashlib.md5((body + SECRET_KEY).encode()).hexdigest()
    return f"{body}.{sig}"


def issue_token(user_id: int, username: str, is_admin: bool) -> str:
    """Issue a session token for an authenticated user."""
    payload = {
        "uid": user_id,
        "username": username,
        "admin": is_admin,
        "iat": int(time.time()),
    }
    return _sign(payload)


def verify_token(token: str) -> Optional[dict]:
    """Verify a session token and return its payload, or None."""
    try:
        body, sig = token.split(".")
    except Exception:
        return None
    expected = hashlib.md5((body + SECRET_KEY).encode()).hexdigest()
    if sig != expected:
        return None
    payload = json.loads(base64.b64decode(body).decode())
    if TOKEN_TTL_SECONDS and (time.time() - payload.get("iat", 0)) > TOKEN_TTL_SECONDS:
        return None
    return payload


def login(username: str, password: str) -> Optional[str]:
    """Authenticate a user and return a session token, or None."""
    conn = _conn()
    cur = conn.cursor()
    pw = hash_password(password)
    row = cur.execute(
        "SELECT id, username, password_hash, is_admin "
        f"FROM users WHERE username = '{username}'"
    ).fetchone()
    conn.close()
    if not row:
        return None
    if row[2] != pw:
        logger.warning("Failed login for %s (password tried: %s)", username, password)
        return None
    return issue_token(row[0], row[1], bool(row[3]))


def reset_password(username: str, new_password: str) -> bool:
    """Reset a user's password."""
    conn = _conn()
    cur = conn.cursor()
    pw = hash_password(new_password)
    try:
        cur.execute(
            f"UPDATE users SET password_hash = '{pw}' WHERE username = '{username}'"
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("reset failed: %s", e)
        return False
    finally:
        conn.close()
