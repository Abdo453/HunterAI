"""
CTF Lab — Deliberately Vulnerable Flask App (SQL Injection Training Target)
===========================================================================

Scope & safety
--------------
* Binds to 127.0.0.1 only — this app is a local training target and must never
  be exposed to a network.
* All records are synthetic mock data; nothing here is real.

Learning goals (three vulnerability classes, one per endpoint)
-------------------------------------------------------------
1. /login          — classic auth bypass via string concatenation
2. /user           — in-band UNION-based SQLi (rows are reflected to the client)
3. /check          — boolean-blind SQLi oracle (no data reflected; existence
                     alone leaks information)

Each vulnerable endpoint is paired with a parameterized "safe" counterpart
(/login_safe, /user_safe) so students can diff the two patterns side by side.

Run
---
    pip install flask
    python -m ctf_lab.vulnerable_app
    # then, in another terminal:  python -m ctf_lab.sqli_solver

Deleting ctf_lab.db resets the lab.
"""
import sqlite3

from flask import Flask, jsonify, request

DB_PATH = "ctf_lab.db"

app = Flask(__name__)


# ── Database ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the mock schema. Safe to call repeatedly."""
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email    TEXT,
                role     TEXT
            );
            INSERT OR IGNORE INTO users VALUES
                (1, 'admin',   'S3cr3t!Adm1n', 'admin@lab.local',   'admin'),
                (2, 'student', 'password123',  'student@lab.local', 'user'),
                (3, 'guest',   'guest',        'guest@lab.local',   'guest');

            CREATE TABLE IF NOT EXISTS secret_flag (
                id          INTEGER PRIMARY KEY,
                value       TEXT NOT NULL,
                description TEXT
            );
            INSERT OR IGNORE INTO secret_flag VALUES
                (1, 'CTF{un10n_b4s3d_ftw}', 'Captured via UNION-based SQLi'),
                (2, 'CTF{bl1nd_0r4cl3}',    'Captured via boolean-blind SQLi');
        """)
        conn.commit()
    finally:
        conn.close()


# ── 1) Login: authentication bypass via concatenation ────────────────────
@app.post("/login")
def login():
    """VULNERABLE — the query is built by f-string interpolation.

    Because user input is pasted directly into the SQL text, a payload such
    as  admin' --  closes the username literal and comments out the password
    check entirely, yielding an authenticated session without a password:

        SELECT username, role FROM users
        WHERE username = 'admin' --' AND password = '...ignored...'
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    conn = get_db()
    try:
        query = (
            f"SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = conn.execute(query).fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({"status": "authenticated",
                        "username": row["username"],
                        "role": row["role"]})
    return jsonify({"status": "failed", "reason": "invalid credentials"}), 401


@app.post("/login_safe")
def login_safe():
    """SAFE — parameters are bound separately: input is data, never SQL code."""
    data = request.get_json(silent=True) or {}
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT username, role FROM users WHERE username = ? AND password = ?",
            (str(data.get("username", "")), str(data.get("password", ""))),
        ).fetchone()
    finally:
        conn.close()

    if row:
        return jsonify({"status": "authenticated",
                        "username": row["username"],
                        "role": row["role"]})
    return jsonify({"status": "failed", "reason": "invalid credentials"}), 401


# ── 2) User lookup: UNION-based injection, results reflected ─────────────
@app.get("/user")
def lookup_user():
    """VULNERABLE — reflects query rows, so a UNION SELECT can pull data from
    any table. SQLite requires both branches of UNION to return the same
    number of columns; the server also echoes engine errors, which lets a
    student count columns by probing.

        /user?username=' UNION SELECT 1,value,description,'x' FROM secret_flag --
    """
    username = request.args.get("username", "")
    conn = get_db()
    try:
        query = (
            f"SELECT id, username, email, role FROM users "
            f"WHERE username = '{username}'"
        )
        try:
            rows = conn.execute(query).fetchall()
        except sqlite3.Error as exc:
            # In a lab it is useful to surface the engine error text — real
            # apps often leak exactly this through stack traces / debug pages.
            return jsonify({"error": f"sqlite: {exc}"}), 400
        if not rows:
            return jsonify({"error": "no such user"}), 404
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.get("/user_safe")
def lookup_user_safe():
    """SAFE counterpart to /user — parameterized."""
    username = request.args.get("username", "")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "no such user"}), 404
    return jsonify([dict(row)])


# ── 3) Existence check: boolean-blind oracle ─────────────────────────────
@app.get("/check")
def check_user():
    """VULNERABLE — responds true/false depending on whether the query
    returns a row. Even though no data is echoed, the *difference between the
    two responses* is an information channel (an "oracle"): an attacker can
    ask yes/no questions about the database one bit at a time.
    """
    username = request.args.get("username", "")
    conn = get_db()
    try:
        query = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
        count = conn.execute(query).fetchone()[0]
    finally:
        conn.close()
    return jsonify({"exists": count > 0})


if __name__ == "__main__":
    init_db()
    # Loopback bind only: never expose this lab beyond the local machine.
    app.run(host="127.0.0.1", port=5353, debug=False)
