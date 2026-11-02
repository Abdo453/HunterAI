#!/usr/bin/env python3
import os
import json
import base64
import jwt
import time
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secret for signing valid JWTs
JWT_SECRET = "lab-coin-secret-2026"
JWT_ALG = "HS256"

# Valid accounts in the system
VALID_ACCOUNTS = {
    "alice": {"uuid": "aaaa-aaaa-aaaa-0001", "password": "alicepass123", "balance": 10000},
    "bob":   {"uuid": "bbbb-bbbb-bbbb-0002", "password": "bobpass456",   "balance": 5000},
    "carol": {"uuid": "cccc-cccc-cccc-0003", "password": "carolpass789", "balance": 8000},
    "dave":  {"uuid": "dddd-dddd-dddd-0004", "password": "davepass000",  "balance": 2000},
}

# Valid payees (merchants)
VALID_PAYEES = {
    "merchant-001": {"name": "Flashpoint Exchange", "uuid": "merchant-001"},
    "merchant-002": {"name": "CoinBase Pro",        "uuid": "merchant-002"},
    "merchant-003": {"name": "Binance Pay",         "uuid": "merchant-003"},
}

# Valid transfer types
VALID_TRANSFER_TYPES = {"1", "2", "3"}

# Rate limiting: max 10 req/s per IP
REQUEST_LOG = {}

def rate_limit(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        REQUEST_LOG[ip] = [t for t in REQUEST_LOG.get(ip, []) if now - t < 1]
        if len(REQUEST_LOG[ip]) >= 10:
            return jsonify({"code": 429, "message": "Rate limited"}), 429
        REQUEST_LOG[ip].append(now)
        return f(*args, **kwargs)
    return wrapped

def create_valid_token(username):
    payload = {"sub": username, "uuid": VALID_ACCOUNTS[username]["uuid"], "iat": int(time.time()), "exp": int(time.time()) + 3600}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.InvalidTokenError:
        return None

def b64decode_safe(s):
    try:
        return base64.b64decode(s).decode()
    except Exception:
        return None

@app.route("/v1/coinMerchant/transfer", methods=["POST"])
@rate_limit
def transfer():
    # Auth: check Authorization Bearer or Cookie ticketId
    auth_header = request.headers.get("Authorization", "")
    cookie_ticket = request.cookies.get("ticketId", "")
    
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    elif cookie_ticket:
        token = cookie_ticket
    
    if not token:
        return jsonify({"code": 401, "message": "Missing authentication token"}), 401
    
    payload = verify_token(token)
    if not payload:
        return jsonify({"code": 401, "message": "Invalid or expired token"}), 401
    
    username = payload.get("sub")
    if username not in VALID_ACCOUNTS:
        return jsonify({"code": 403, "message": "Account not found"}), 403
    
    # Parse JSON body
    data = request.get_json(silent=True) or {}
    payee_uuid = data.get("payeeUuid")
    order_amount = data.get("orderAmount")
    password_b64 = data.get("password")
    transfer_type = data.get("transferType")
    
    # Validate required fields
    if not all([payee_uuid, order_amount, password_b64, transfer_type]):
        return jsonify({"code": 400, "message": "Missing required fields"}), 400
    
    # Validate payee exists
    if payee_uuid not in VALID_PAYEES:
        return jsonify({"code": 400, "message": "Invalid payeeUuid"}), 400
    
    # Validate transfer type
    if transfer_type not in VALID_TRANSFER_TYPES:
        return jsonify({"code": 400, "message": "Invalid transferType"}), 400
    
    # Validate amount
    try:
        amount = int(order_amount)
        if amount <= 0:
            return jsonify({"code": 400, "message": "Amount must be positive"}), 400
    except ValueError:
        return jsonify({"code": 400, "message": "Invalid orderAmount"}), 400
    
    # Validate password
    decoded_pw = b64decode_safe(password_b64)
    if decoded_pw != VALID_ACCOUNTS[username]["password"]:
        return jsonify({"code": 401, "message": "Invalid password"}), 401
    
    # Check balance
    if VALID_ACCOUNTS[username]["balance"] < amount:
        return jsonify({"code": 400, "message": "Insufficient balance"}), 400
    
    # Success
    VALID_ACCOUNTS[username]["balance"] -= amount
    return jsonify({
        "code": 200,
        "message": "Transfer successful",
        "data": {
            "transferId": f"TXN-{int(time.time())}-{username}",
            "payeeUuid": payee_uuid,
            "amount": amount,
            "remainingBalance": VALID_ACCOUNTS[username]["balance"]
        }
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    # Print valid tokens for the attacker to discover
    print("=== VALID TOKENS (for reference) ===")
    for user in VALID_ACCOUNTS:
        tok = create_valid_token(user)
        print(f"{user}: {tok}")
    print("=== VALID PAYEES ===")
    for k, v in VALID_PAYEES.items():
        print(f"  {k}: {v['name']}")
    print("=== VALID PASSWORDS (base64) ===")
    for user, info in VALID_ACCOUNTS.items():
        print(f"  {user}: {base64.b64encode(info['password'].encode()).decode()}")
    print("=== VALID TRANSFER TYPES: 1, 2, 3 ===")
    app.run(host="0.0.0.0", port=5000)