#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
purge_old_targets.py — Purge old target and past scan artifacts
===============================================================
Cleans out previous engagement remnants, past test scans, old dossiers,
and intercepted traffic databases to give the agent a clean slate.
"""

from pathlib import Path
import shutil

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"

purged_items = []

# 1. Clean data/reports/
reports_dir = DATA_DIR / "reports"
if reports_dir.exists():
    for item in reports_dir.iterdir():
        if item.is_file() and any(k in item.name.lower() for k in ["dossier", "hackerone", "192.168"]):
            try:
                item.unlink()
                purged_items.append(f"Report File: {item.name}")
            except Exception as e:
                print(f"Error removing {item}: {e}")
        elif item.is_dir() and item.name in ["test.com", "testcorp.com"]:
            try:
                shutil.rmtree(item)
                purged_items.append(f"Report Dir: {item.name}")
            except Exception as e:
                print(f"Error removing dir {item}: {e}")

# 2. Clean data/scans/
scans_dir = DATA_DIR / "scans"
if scans_dir.exists():
    for item in scans_dir.iterdir():
        if item.is_dir():
            try:
                shutil.rmtree(item)
                purged_items.append(f"Scan Dir: {item.name}")
            except Exception as e:
                print(f"Error removing {item}: {e}")

# 3. Clean data/tool_outputs/
tool_out_dir = DATA_DIR / "tool_outputs"
if tool_out_dir.exists():
    for item in tool_out_dir.iterdir():
        if item.is_file():
            try:
                item.unlink()
                purged_items.append(f"Tool Output: {item.name}")
            except Exception as e:
                print(f"Error removing {item}: {e}")

# 4. Clean old engagement states state_ENG-*.json
for state_file in DATA_DIR.glob("state_ENG-*.json"):
    try:
        state_file.unlink()
        purged_items.append(f"Engagement State: {state_file.name}")
    except Exception as e:
        print(f"Error removing {state_file}: {e}")

# 5. Reset intercepted_api.json and traffic dbs
intercepted_file = DATA_DIR / "intercepted_api.json"
if intercepted_file.exists():
    intercepted_file.write_text("{}", encoding="utf-8")
    purged_items.append("Reset intercepted_api.json")

for db_name in ["traffic.db", "cert_traffic.db"]:
    db_file = DATA_DIR / db_name
    if db_file.exists():
        try:
            db_file.unlink()
            purged_items.append(f"Purged DB: {db_name}")
        except Exception as e:
            print(f"Error removing {db_file}: {e}")

print("=" * 60)
print(f"PURGE COMPLETE: Removed {len(purged_items)} old target remnants!")
for item in purged_items[:20]:
    print(f"  - {item}")
if len(purged_items) > 20:
    print(f"  ... and {len(purged_items) - 20} more items.")
print("=" * 60)
