"""
Endpoint Analyzer & Application Map Builder for BurpAgent
"""
import time
import logging
from typing import Optional
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel, EndpointModel
from agents.burp_agent.core.normalizer import URLNormalizer
from agents.burp_agent.storage.database import TrafficDatabase

log = logging.getLogger("burp_agent.endpoint_analyzer")


class EndpointAnalyzer:
    """بناء خريطة التطبيق الهيكلية (Application Map) وتتبع الـ Endpoints"""

    def __init__(self, db: TrafficDatabase):
        self.db = db

    async def analyze(self, req: HTTPRequestModel, resp: Optional[HTTPResponseModel] = None):
        norm_path, path_params = URLNormalizer.normalize_path(req.path)
        ep_id = f"{req.method.upper()} {req.host}{norm_path}"

        is_api = "/api" in norm_path.lower() or "/v1" in norm_path.lower() or "/v2" in norm_path.lower() or "/graphql" in norm_path.lower()
        is_admin = "/admin" in norm_path.lower() or "/manage" in norm_path.lower() or "/dashboard" in norm_path.lower()

        status_codes = [resp.status_code] if resp else []
        param_names = [p.name for p in req.parameters] + path_params

        auth_req = bool(req.headers.get("Authorization") or req.cookies.get("session") or req.cookies.get("token"))
        auth_types = []
        if req.headers.get("Authorization"):
            auth_types.append("Bearer/Basic")
        if req.cookies:
            auth_types.append("Cookie")

        ep_model = EndpointModel(
            id=ep_id,
            host=req.host,
            method=req.method.upper(),
            normalized_path=norm_path,
            raw_paths=[req.path],
            parameters=list(set(param_names)),
            auth_required=auth_req,
            auth_types=auth_types,
            status_codes_seen=status_codes,
            first_seen=time.time(),
            last_seen=time.time(),
            is_api=is_api,
            is_admin=is_admin
        )
        self.db.upsert_endpoint(ep_model)
