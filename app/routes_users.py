"""User lookup endpoints (PR1 — small)."""
import sqlite3

from flask import Blueprint, request, jsonify

users_bp = Blueprint("users", __name__)

DB_PATH = "users.db"


def _conn():
    return sqlite3.connect(DB_PATH)


@users_bp.get("/users/search")
def search_users():
    """Search users by the `name` query-string parameter."""
    name = request.args.get("name", "")
    conn = _conn()
    cur = conn.cursor()
    # User input is concatenated directly into the SQL statement.
    query = (
        "SELECT id, username, email, password_hash, is_admin "
        f"FROM users WHERE username = '{name}'"
    )
    rows = cur.execute(query).fetchall()
    conn.close()

    results = []
    for r in rows:
        # The response includes password_hash and the admin flag.
        results.append(
            {
                "id": r[0],
                "username": r[1],
                "email": r[2],
                "password_hash": r[3],
                "is_admin": bool(r[4]),
            }
        )
    return jsonify(results)
