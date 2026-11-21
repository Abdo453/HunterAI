#!/usr/bin/env python3
"""
PENTEST-AI UNIFIED — ONE-COMMAND MAXIMUM POWER RUNNER
تشغيل الوكيل الشامل بأقصى طاقة واستخدام كافة النماذج الستة 1 -> 6 بأمر واحد
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from scripts.master_agent import launch_full_power

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        from scripts.master_agent import banner
        banner()
        print("Usage: python master.py [target_or_prompt]\n")
        sys.exit(0)
    target = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "target.com"
    launch_full_power(target)
