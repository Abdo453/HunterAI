"""
HTTP Parser & Deserializer for BurpAgent
Parses raw HTTP/1.1 wire requests and responses, JSON payloads, form data, and multipart uploads.
"""
import re
import json
import uuid
import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from agents.burp_agent.storage.models import (
    HTTPRequestModel, HTTPResponseModel, ParameterModel,
    ParameterLocation, TriagePriority
)

log = logging.getLogger("burp_agent.parser")


class HTTPParser:
    """محلل الطلبات والردود الخام وتحويلها لكائنات مهيكلة"""

    @staticmethod
    def parse_raw_request(
        raw_http: str,
        host: Optional[str] = None,
        port: int = 80,
        protocol: str = "http",
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> HTTPRequestModel:
        """تحليل طلب HTTP خام (RFC 7230 / RFC 2616)"""
        req_id = f"req_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
        lines = raw_http.replace("\r\n", "\n").split("\n")
        if not lines or not lines[0].strip():
            raise ValueError("Empty HTTP request")

        # 1. Parse Request Line
        first_line = lines[0].strip()
        parts = first_line.split(" ")
        method = parts[0].upper() if len(parts) > 0 else "GET"
        raw_url = parts[1] if len(parts) > 1 else "/"

        # 2. Parse Headers & Body
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        body_lines = []
        is_body = False

        for line in lines[1:]:
            if not is_body:
                if line == "":
                    is_body = True
                    continue
                if ":" in line:
                    h_key, h_val = line.split(":", 1)
                    k_clean = h_key.strip()
                    v_clean = h_val.strip()
                    headers[k_clean] = v_clean
                    if k_clean.lower() == "cookie":
                        for c in v_clean.split(";"):
                            if "=" in c:
                                ck, cv = c.strip().split("=", 1)
                                cookies[ck.strip()] = cv.strip()
            else:
                body_lines.append(line)

        body = "\n".join(body_lines) if body_lines else None
        body_len = len(body.encode("utf-8")) if body else 0

        # Determine Host & URL
        h_hdr = headers.get("Host") or headers.get("host") or host or "localhost"
        if ":" in h_hdr and port == 80:
            h_parts = h_hdr.split(":")
            h_host = h_parts[0]
            try:
                port = int(h_parts[1])
            except ValueError:
                pass
        else:
            h_host = h_hdr

        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            full_url = raw_url
            parsed_u = urlparse(full_url)
            path = parsed_u.path or "/"
            query_str = parsed_u.query
            protocol = parsed_u.scheme
        else:
            path = raw_url.split("?")[0] if "?" in raw_url else raw_url
            query_str = raw_url.split("?")[1] if "?" in raw_url else ""
            port_str = f":{port}" if (port != 80 and port != 443) else ""
            full_url = f"{protocol}://{h_host}{port_str}{path}"
            if query_str:
                full_url += f"?{query_str}"

        # 3. Extract Parameters
        params: List[ParameterModel] = []

        # Query Parameters
        if query_str:
            qs = parse_qs(query_str, keep_blank_values=True)
            for qk, qvals in qs.items():
                for qv in qvals:
                    params.append(ParameterModel(
                        request_id=req_id,
                        name=qk,
                        value=qv,
                        location=ParameterLocation.QUERY,
                        is_user_controlled_id=HTTPParser._is_user_id_param(qk, qv),
                        is_role_indicator=HTTPParser._is_role_param(qk, qv)
                    ))

        # Body Parameters (Form URL-Encoded or JSON)
        c_type = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        if body:
            if "application/json" in c_type or body.strip().startswith(("{", "[")):
                try:
                    json_obj = json.loads(body)
                    HTTPParser._extract_json_params(json_obj, req_id, params)
                except Exception:
                    pass
            elif "application/x-www-form-urlencoded" in c_type or "=" in body:
                bs = parse_qs(body, keep_blank_values=True)
                for bk, bvals in bs.items():
                    for bv in bvals:
                        params.append(ParameterModel(
                            request_id=req_id,
                            name=bk,
                            value=bv,
                            location=ParameterLocation.BODY,
                            is_user_controlled_id=HTTPParser._is_user_id_param(bk, bv),
                            is_role_indicator=HTTPParser._is_role_param(bk, bv)
                        ))

        # Cookie Parameters
        for ck, cv in cookies.items():
            params.append(ParameterModel(
                request_id=req_id,
                name=ck,
                value=cv,
                location=ParameterLocation.COOKIE,
                is_sensitive=ck.lower() in ("session", "token", "auth", "jwt", "sessionid", "connect.sid")
            ))

        return HTTPRequestModel(
            id=req_id,
            session_id=session_id,
            timestamp=time.time(),
            host=h_host,
            port=port,
            protocol=protocol,
            method=method,
            url=full_url,
            path=path,
            query_string=query_str,
            headers=headers,
            cookies=cookies,
            body=body,
            body_length=body_len,
            content_type=c_type or None,
            parameters=params,
            client_ip=client_ip,
            raw_request=raw_http
        )

    @staticmethod
    def parse_raw_response(
        raw_http: str,
        request_id: str,
        response_time_ms: float = 0.0
    ) -> HTTPResponseModel:
        """تحليل رد HTTP خام"""
        resp_id = f"resp_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
        lines = raw_http.replace("\r\n", "\n").split("\n")
        if not lines or not lines[0].strip():
            raise ValueError("Empty HTTP response")

        # 1. Status Line
        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)
        status_code = 200
        status_msg = "OK"
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass
        if len(parts) >= 3:
            status_msg = parts[2]

        # 2. Headers & Body
        headers: Dict[str, str] = {}
        body_lines = []
        is_body = False

        for line in lines[1:]:
            if not is_body:
                if line == "":
                    is_body = True
                    continue
                if ":" in line:
                    hk, hv = line.split(":", 1)
                    headers[hk.strip()] = hv.strip()
            else:
                body_lines.append(line)

        body = "\n".join(body_lines) if body_lines else None
        body_len = len(body.encode("utf-8")) if body else 0
        c_type = headers.get("Content-Type") or headers.get("content-type")
        server = headers.get("Server") or headers.get("server")

        # Tech detection
        techs = []
        if server:
            techs.append(server)
        powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered:
            techs.append(powered)

        return HTTPResponseModel(
            id=resp_id,
            request_id=request_id,
            timestamp=time.time(),
            status_code=status_code,
            status_message=status_msg,
            headers=headers,
            body=body,
            body_length=body_len,
            content_type=c_type,
            response_time_ms=response_time_ms,
            server_banner=server,
            technologies=techs,
            raw_response=raw_http
        )

    @staticmethod
    def _is_user_id_param(name: str, value: str) -> bool:
        n_low = name.lower()
        id_indicators = ["id", "user_id", "userid", "account_id", "uid", "profile_id", "member_id"]
        return n_low in id_indicators or (n_low.endswith("_id") and (value.isdigit() or len(value) == 36))

    @staticmethod
    def _is_role_param(name: str, value: str) -> bool:
        n_low = name.lower()
        role_indicators = ["role", "group", "is_admin", "admin", "privilege", "type", "permission"]
        return n_low in role_indicators

    @staticmethod
    def _extract_json_params(obj: Any, req_id: str, params: List[ParameterModel], prefix: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                p_name = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    HTTPParser._extract_json_params(v, req_id, params, p_name)
                else:
                    v_str = str(v)
                    params.append(ParameterModel(
                        request_id=req_id,
                        name=p_name,
                        value=v_str,
                        location=ParameterLocation.JSON,
                        is_user_controlled_id=HTTPParser._is_user_id_param(p_name, v_str),
                        is_role_indicator=HTTPParser._is_role_param(p_name, v_str)
                    ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                HTTPParser._extract_json_params(item, req_id, params, f"{prefix}[{i}]")
