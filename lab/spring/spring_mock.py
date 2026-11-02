import os
import logging
import socket
import urllib.parse
import json
import time
import base64
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
LOG_DIR = "/var/log/app"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=f"{LOG_DIR}/spring.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)

# In-memory user store
USERS = {}

# JWT secret for mock tokens
JWT_SECRET = "lab-auth-secret-2026"

def create_mock_jwt(username):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "roles": ["user"]
    }
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}"
    import hmac
    import hashlib
    signature = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{signing_input}.{signature_b64}"


def do_gopher(url):
    u = urlparse(url)
    host = u.hostname
    port = u.port or 70
    raw = u.path
    if raw.startswith("/_"):
        raw = raw[2:]
    elif raw.startswith("/"):
        raw = raw[1:]
    data = urllib.parse.unquote_to_bytes(raw)
    sock = socket.create_connection((host, port), timeout=5)
    try:
        sock.sendall(data)
        sock.settimeout(3)
        chunks = []
        try:
            while True:
                buf = sock.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        except socket.timeout:
            pass
        return b"".join(chunks).decode("utf-8", "replace")
    finally:
        sock.close()


@app.before_request
def log_request():
    logging.info(
        "REQ %s %s ua=%s",
        request.method,
        request.path,
        request.headers.get("User-Agent", ""),
    )


@app.post("/api/fetch")
def fetch():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url") or request.args.get("url")
    method = (data.get("method") or "GET").upper()
    headers = data.get("headers") or {}
    if not url:
        return jsonify(error="url required"), 400
    try:
        if url.startswith("gopher://"):
            body = do_gopher(url)
            return jsonify(status=200, scheme="gopher", body=body[:4000])
        resp = requests.request(
            method, url, headers=headers, timeout=5, allow_redirects=False
        )
        return jsonify(status=resp.status_code, scheme="http", body=resp.text[:4000])
    except Exception as exc:
        return jsonify(error=f"{type(exc).__name__}: {exc}"), 502


@app.get("/api/file")
def lfi():
    path = request.args.get("path", "")
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read()
    except Exception as exc:
        return jsonify(error=str(exc)), 404


@app.post("/api/UserController/add")
def add_user():
    data = request.get_json(force=True, silent=True) or {}
    logging.info(
        "USER_ADD account=%s nickName=%s",
        data.get("account", ""),
        data.get("nickName", ""),
    )
    return jsonify(msg="ok", status=200)


@app.post("/api/register")
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify(status="error", message="username and password required"), 400
    if username in USERS:
        return jsonify(status="error", message="user already exists"), 409
    USERS[username] = password
    logging.info("REGISTER username=%s", username)
    return jsonify(status="success")


@app.post("/api/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify(status="error", message="username and password required"), 400
    if USERS.get(username) != password:
        logging.info("LOGIN_FAILED username=%s", username)
        return jsonify(status="error", message="invalid credentials"), 401
    token = create_mock_jwt(username)
    logging.info("LOGIN_SUCCESS username=%s", username)
    return jsonify(status="success", token=token)


@app.get("/api/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
