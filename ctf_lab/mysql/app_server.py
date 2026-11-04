"""
CTF Lab (MySQL) — Deliberately Vulnerable App Server
====================================================

Same three vulnerability classes as the SQLite lab (ctf_lab/vulnerable_app.py),
but against a separate MySQL backend running in Docker:

  1. POST /login   — auth bypass via concatenation (MySQL quote/comment syntax)
  2. GET  /user    — UNION-based SQLi with reflected rows
  3. GET  /check   — boolean-blind oracle ({"exists": true|false})

Each vulnerable endpoint has a parameterized safe counterpart so students can
diff the patterns.

Run (host side):
    docker compose up -d --build      # from ctf_lab/mysql/
    open  http://127.0.0.1:5354/      # healthcheck page

Scope: published on 127.0.0.1:5354 only (docker-compose port mapping).
"""
import os

import pymysql
from flask import Flask, jsonify, request

app = Flask(__name__)


# ── Database connection ───────────────────────────────────────────────────
def get_conn():
    """Fresh connection per request — fine for a single-user lab.

    The account (labuser) is least-privileged by design: full rights on
    ctf_lab, nothing else. The blind solver therefore tops out at this
    schema, which is exactly the lesson.
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST", "mysql-lab"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "labuser"),
        password=os.getenv("DB_PASSWORD", "labpass"),
        database=os.getenv("DB_NAME", "ctf_lab"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


# ── 1) Login: auth bypass via concatenation ──────────────────────────────
@app.post("/login")
def login():
    """VULNERABLE — user input is pasted into the SQL text.

    MySQL specifics the SQLite lab could not show:
      * `'` closes a string literal; backslash is an escape character.
      * `--` only starts a comment when followed by a space/control char,
        which is why real payloads write `-- -` (embedded space).
      * `#` is the other line comment; `/* */` is inline.
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    conn = get_conn()
    try:
        query = (
            f"SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        with conn.cursor() as cur:
            row = cur.execute(query).fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({"status": "authenticated",
                        "username": row["username"],
                        "role": row["role"]})
    return jsonify({"status": "failed", "reason": "invalid credentials"}), 401


@app.post("/login_safe")
def login_safe():
    """SAFE — same pymysql API, but values travel as bound parameters."""
    data = request.get_json(silent=True) or {}
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            row = cur.execute(
                "SELECT username, role FROM users WHERE username = %s AND password = %s",
                (str(data.get("username", "")), str(data.get("password", ""))),
            ).fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({"status": "authenticated",
                        "username": row["username"],
                        "role": row["role"]})
    return jsonify({"status": "failed", "reason": "invalid credentials"}), 401


# ── 2) User lookup: UNION-based, rows reflected ──────────────────────────
@app.get("/user")
def lookup_user():
    """VULNERABLE — mirrors /user from the SQLite lab.

    MySQL-side gotchas a student will hit here:
      * Column COUNT must match on both UNION branches; a mismatch raises
        "The used SELECT statements have a different number of columns"
        (the 400 body leaks it — realistic error-based recon).
      * MySQL constrains a UNION to injectable literals like NULL without
        column-name knowledge, exactly like SQLite.
    """
    username = request.args.get("username", "")
    conn = get_conn()
    try:
        query = (
            f"SELECT id, username, email, role FROM users "
            f"WHERE username = '{username}'"
        )
        with conn.cursor() as cur:
            try:
                rows = cur.execute(query).fetchall()
            except pymysql.MySQLError as exc:
                # Lab choice: surface engine errors like leaky debug pages do.
                return jsonify({"error": f"mysql: {exc}"}), 400
        if not rows:
            return jsonify({"error": "no such user"}), 404
        return jsonify(rows)
    finally:
        conn.close()


@app.get("/user_safe")
def lookup_user_safe():
    """SAFE counterpart to /user."""
    username = request.args.get("username", "")
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            row = cur.execute(
                "SELECT id, username, email, role FROM users WHERE username = %s",
                (username,),
            ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "no such user"}), 404
    return jsonify([row])


# ── 3) Existence check: boolean-blind oracle ─────────────────────────────
@app.get("/check")
def check_user():
    """VULNERABLE — the single response bit the whole blind solver runs on:
    {"exists": true} iff COUNT(*) > 0.

    MySQL nuance kept for teaching: string comparison uses the default
    collation (case-insensitive here), and CHAR/VARCHAR comparisons ignore
    trailing spaces — two real-world oracle quirks worth knowing.
    """
    username = request.args.get("username", "")
    conn = get_conn()
    try:
        query = f"SELECT COUNT(*) AS c FROM users WHERE username = '{username}'"
        with conn.cursor() as cur:
            count = cur.execute(query).fetchone()["c"]
    finally:
        conn.close()
    return jsonify({"exists": bool(count)})


@app.get("/")
def index():
    return jsonify({"lab": "ctf-mysql",
                    "endpoints": ["/login", "/user", "/check",
                                  " (+ /login_safe, /user_safe)"]})


if __name__ == "__main__":
    # In-container bind: 0.0.0.0 is required for Docker NAT; the loopback
    # guarantee is made host-side by the compose port mapping.
    app.run(host="0.0.0.0", port=5354)
