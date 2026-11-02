#!/usr/bin/env python3
"""
Lab Auth Extractor - Automates register -> login -> token extraction
"""
import json
import secrets
import string
import sys
import requests

BASE = "http://127.0.0.1:8088"

def generate_credentials():
    username = f"testuser_{secrets.randbelow(100000):05d}"
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    return username, password

def register(username, password):
    url = f"{BASE}/api/register"
    payload = {"username": username, "password": password}
    r = requests.post(url, json=payload, timeout=10)
    return r.status_code, r.json()

def login(username, password):
    url = f"{BASE}/api/login"
    payload = {"username": username, "password": password}
    r = requests.post(url, json=payload, timeout=10)
    return r.status_code, r.json()

def main():
    print("[*] Generating random credentials...")
    username, password = generate_credentials()
    print(f"    Username: {username}")
    print(f"    Password: {password}")
    
    print("\n[*] Registering user...")
    status, resp = register(username, password)
    print(f"    HTTP {status}: {json.dumps(resp)}")
    if status != 200 or resp.get("status") != "success":
        print("[!] Registration failed")
        sys.exit(1)
    
    print("\n[*] Logging in...")
    status, resp = login(username, password)
    print(f"    HTTP {status}: {json.dumps(resp)}")
    if status != 200 or resp.get("status") != "success":
        print("[!] Login failed")
        sys.exit(1)
    
    token = resp.get("token")
    if not token:
        print("[!] No token in response")
        sys.exit(1)
    
    print(f"\n[+] Successfully extracted token: {token}")
    
    output = {
        "username": username,
        "password": password,
        "token": token
    }
    with open("extracted_auth.json", "w") as f:
        json.dump(output, f, indent=2)
    print("[+] Saved credentials and token to extracted_auth.json")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())