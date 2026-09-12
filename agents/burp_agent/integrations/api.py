"""
FastAPI Router for HunterAI BurpAgent Monitoring & Control
"""
from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any

def create_burp_api_router(burp_agent_instance) -> APIRouter:
    router = APIRouter(prefix="/api/burp", tags=["BurpAgent"])

    @router.get("/stats")
    async def get_stats():
        """إحصائيات الترافيك المباشر والـ Endpoints والـ Findings"""
        return burp_agent_instance.get_stats()

    @router.get("/endpoints")
    async def get_endpoints(host: str = ""):
        """خريطة الـ Endpoints والباراميترات المكتشفة"""
        return {"endpoints": burp_agent_instance.db.list_endpoints(host or None)}

    @router.get("/findings")
    async def get_findings():
        """الثغرات المكتشفة المدعومة بالأدلة الجنائية"""
        return {"findings": burp_agent_instance.db.list_findings()}

    @router.get("/graph")
    async def get_attack_graph():
        """شجرة مسارات الهجوم والعلاقات المكتشفة"""
        return burp_agent_instance.db.get_attack_graph()

    @router.post("/scope")
    async def update_scope(req: Request):
        """تحديث نطاق الفحص المسموح"""
        data = await req.json()
        includes = data.get("include", [])
        excludes = data.get("exclude", [])
        for inc in includes:
            burp_agent_instance.scope.add_include(inc)
        for exc in excludes:
            burp_agent_instance.scope.add_exclude(exc)
        return {"status": "updated", "include": burp_agent_instance.scope.include_rules, "exclude": burp_agent_instance.scope.exclude_rules}

    return router
