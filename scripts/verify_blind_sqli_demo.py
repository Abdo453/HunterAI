#!/usr/bin/env python3
"""
Demo script to verify that the built‑in SQLiSkill can perform a blind boolean
SQL injection and detect the "Welcome back" indicator.
It does **not** contact a real server – it uses the internal mock detector
logic exercised by the unit‑tests.
"""
import asyncio
from agents.skills.sqli_skill import SQLiSkill, SQLiContext, DBMSType

async def main():
    # Mock target – the actual URL is irrelevant for the demonstration.
    target_url = "http://example.com/?category=1"
    param_name = "category"
    # Initialise the skill with a dummy objective (we just want the blind flow).
    skill = SQLiSkill(objective="blind_test")
    # Run the skill; it will internally use the blind_boolean payloads.
    result = await skill.run(target_url=target_url, param_name=param_name)
    # Print a concise summary.
    print("=== Blind‑SQLi Demo Result ===")
    print(f"State:            {result.get('state')}")
    print(f"Objective met:    {result.get('objective_met')}")
    print(f"Extracted data:   {result.get('extracted_data')}")
    # The detection of the "Welcome back" message is encoded in the
    # SQLiObjectiveChecker – if it succeeded, the lab is solved.
    if result.get('objective_met'):
        print("✅  Blind‑SQLi detection works – lab can be solved.")
    else:
        print("❌  Detection failed – check payload/config.")

if __name__ == "__main__":
    asyncio.run(main())
