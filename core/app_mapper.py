"""
Application Topology & State Graph Mapper
Builds a hierarchical tree and state graph of the target web application (Authentication, User Area, APIs, Admin Surface) from KnowledgeDB.
"""
from __future__ import annotations

import json
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.database.knowledge_db import KnowledgeDB


class ApplicationMapper:
    """
    راسم خريطة وهيكل التطبيق (Application Topology & State Graph Mapper):
    - يجمع كل الـ Endpoints والـ Forms والـ UI Actions من قاعدة المعرفة.
    - يقسم المسارات إلى شجرة هرمية وظيفية (Auth -> User -> API -> Admin).
    - يولد تمثيلاً مرئياً (ASCII Tree & Mermaid Diagram) لتغذية الـ LLM والتقارير.
    """

    def __init__(self, db: KnowledgeDB):
        self.db = db

    def build_application_tree(self, target: str) -> Dict[str, Any]:
        """بناء الشجرة الهيكلية للتطبيق"""
        with self.db._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM endpoints")
            endpoints = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT * FROM ui_traffic_correlations")
            correlations = [dict(row) for row in cursor.fetchall()]

        tree = {
            "target": target,
            "authentication": [],
            "user_features": [],
            "api_layer": [],
            "admin_surface": [],
            "other_endpoints": []
        }

        for ep in endpoints:
            url = ep.get("url", "")
            path = ep.get("path", "").lower()
            cat = ep.get("category", "").lower()
            method = ep.get("method", "GET")
            entry = f"[{method}] {ep.get('path')} ({url})"

            if cat == "auth" or any(k in path for k in ("login", "signin", "register", "signup", "auth", "token", "password", "logout")):
                tree["authentication"].append(entry)
            elif cat == "admin" or any(k in path for k in ("admin", "manage", "internal", "config", "debug")):
                tree["admin_surface"].append(entry)
            elif cat == "api" or any(k in path for k in ("/api/", "graphql", "swagger", "openapi")):
                tree["api_layer"].append(entry)
            elif cat == "user" or any(k in path for k in ("profile", "user", "account", "settings", "cart")):
                tree["user_features"].append(entry)
            else:
                tree["other_endpoints"].append(entry)

        return tree

    def generate_ascii_tree(self, target: str) -> str:
        """توليد خريطة نصية شجرية ASCII سهلة القراءة"""
        tree = self.build_application_tree(target)
        lines = [
            f"Application Map for: {target}",
            "=========================================",
            f"{target}",
            "│",
            "├── 🔐 Authentication Surface",
        ]

        if tree["authentication"]:
            for item in tree["authentication"][:8]:
                lines.append(f"│   ├── {item}")
        else:
            lines.append("│   └── (No explicit auth endpoints recorded)")

        lines.extend([
            "│",
            "├── 👤 User Features & Resources",
        ])
        if tree["user_features"]:
            for item in tree["user_features"][:8]:
                lines.append(f"│   ├── {item}")
        else:
            lines.append("│   └── (No user resources recorded)")

        lines.extend([
            "│",
            "├── ⚡ API Endpoints & Routes",
        ])
        if tree["api_layer"]:
            for item in tree["api_layer"][:8]:
                lines.append(f"│   ├── {item}")
        else:
            lines.append("│   └── (No API routes recorded)")

        lines.extend([
            "│",
            "└── 🛡️ Admin & Internal Perimeter",
        ])
        if tree["admin_surface"]:
            for item in tree["admin_surface"][:8]:
                lines.append(f"    ├── {item}")
        else:
            lines.append("    └── (No admin endpoints recorded)")

        return "\n".join(lines)

    def generate_mermaid_diagram(self, target: str) -> str:
        """توليد رسم بياني بصيغة Mermaid لتضمينه في التقرير والـ UI"""
        tree = self.build_application_tree(target)
        lines = [
            "```mermaid",
            "graph TD",
            f'    Root["{target}"]',
            '    Root --> Auth["🔐 Authentication"]',
            '    Root --> User["👤 User Area"]',
            '    Root --> API["⚡ API Surface"]',
            '    Root --> Admin["🛡️ Admin Perimeter"]',
        ]

        for idx, item in enumerate(tree["authentication"][:4], 1):
            lines.append(f'    Auth --> A{idx}["{item[:35]}"]')
        for idx, item in enumerate(tree["user_features"][:4], 1):
            lines.append(f'    User --> U{idx}["{item[:35]}"]')
        for idx, item in enumerate(tree["api_layer"][:4], 1):
            lines.append(f'    API --> API{idx}["{item[:35]}"]')
        for idx, item in enumerate(tree["admin_surface"][:4], 1):
            lines.append(f'    Admin --> AD{idx}["{item[:35]}"]')

        lines.append("```")
        return "\n".join(lines)

    def export_all(self, workspace_path: Path, target: str) -> Dict[str, Path]:
        """تصدير ملفات خريطة التطبيق في مسار الـ Workspace"""
        app_dir = workspace_path / "app_map"
        app_dir.mkdir(parents=True, exist_ok=True)

        tree = self.build_application_tree(target)
        json_path = app_dir / "application_map.json"
        json_path.write_text(json.dumps(tree, indent=2), encoding="utf-8")

        ascii_path = app_dir / "application_map.txt"
        ascii_path.write_text(self.generate_ascii_tree(target), encoding="utf-8")

        mermaid_path = app_dir / "application_graph.mmd"
        mermaid_path.write_text(self.generate_mermaid_diagram(target), encoding="utf-8")

        return {
            "json": json_path,
            "ascii": ascii_path,
            "mermaid": mermaid_path
        }
