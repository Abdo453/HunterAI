"""
HunterAI Control Center — FastAPI Routers Package
=================================================
Collects and exports all modular API routers for the Web Control Center.
"""
from __future__ import annotations

from ui.web.routers.agents import router as agents_router
from ui.web.routers.emergency import router as emergency_router
from ui.web.routers.mcp import router as mcp_router
from ui.web.routers.operations import router as operations_router
from ui.web.routers.scope import router as scope_router

ALL_ROUTERS = [
    agents_router,
    scope_router,
    emergency_router,
    mcp_router,
    operations_router,
]

__all__ = [
    "ALL_ROUTERS",
    "agents_router",
    "scope_router",
    "emergency_router",
    "mcp_router",
    "operations_router",
]
