"""Copilot REST & SSE Streaming API Router (`/api/copilot/*`)."""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.copilot_service import CopilotService

logger = logging.getLogger("hunter_ai.copilot_api")

router = APIRouter(prefix="/api/copilot", tags=["copilot"])


def _get_service() -> CopilotService:
    return CopilotService()


class ConversationCreateRequest(BaseModel):
    title: str = "New Investigation"
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    mode: str = "analyst"
    model: str = "auto"
    set_active: bool = True


class ConversationPatchRequest(BaseModel):
    title: Optional[str] = None
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    mode: Optional[str] = None
    model: Optional[str] = None


class ChatStreamRequest(BaseModel):
    message: str = Field(..., min_length=1)
    conversation_id: Optional[str] = None
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    model: Optional[str] = None
    mode: Optional[str] = None
    attachment_ids: List[str] = Field(default_factory=list)


def _format_sse(event: str, data: Dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"


@router.get("/conversations")
async def list_conversations(
    engagement_id: Optional[str] = None,
    run_id: Optional[str] = None,
    limit: int = 100,
):
    svc = _get_service()
    items = svc.list_conversations(engagement_id=engagement_id, run_id=run_id, limit=limit)
    return {"status": "ok", "count": len(items), "conversations": items}


@router.post("/conversations")
async def create_conversation(req: ConversationCreateRequest):
    svc = _get_service()
    conv = svc.create_conversation(
        title=req.title,
        engagement_id=req.engagement_id,
        run_id=req.run_id,
        mode=req.mode,
        model=req.model,
        set_active=req.set_active,
    )
    return {"status": "ok", "conversation": conv}


@router.get("/conversations/{cid}")
async def get_conversation(cid: str):
    svc = _get_service()
    detail = svc.get_conversation_detail(cid)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Conversation '{cid}' not found")
    return {"status": "ok", **detail}


@router.patch("/conversations/{cid}")
async def patch_conversation(cid: str, req: ConversationPatchRequest):
    svc = _get_service()
    updated = svc.update_conversation(
        cid,
        title=req.title,
        engagement_id=req.engagement_id,
        run_id=req.run_id,
        mode=req.mode,
        model=req.model,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Conversation '{cid}' not found")
    return {"status": "ok", "conversation": updated}


@router.delete("/conversations/{cid}")
async def delete_conversation(cid: str):
    svc = _get_service()
    ok = svc.delete_conversation(cid)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Conversation '{cid}' not found")
    return {"status": "ok", "deleted": True, "conversation_id": cid}


@router.post("/attachments")
async def upload_attachment(
    request: Request,
    file: Optional[UploadFile] = File(default=None),
    conversation_id: Optional[str] = Form(default=None),
):
    svc = _get_service()
    if file is not None:
        raw = await file.read()
        try:
            att = svc.store_attachment(
                filename=file.filename or "upload.txt",
                raw_bytes=raw,
                content_type=file.content_type or "text/plain",
                conversation_id=conversation_id,
            )
            return {"status": "ok", "attachment": att}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Support JSON fallback payload {filename, content, conversation_id}
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Multipart file or JSON body required") from exc

    filename = str(body.get("filename") or "snippet.txt")
    content = str(body.get("content") or "")
    conv_id = body.get("conversation_id") or conversation_id
    if not content:
        raise HTTPException(status_code=400, detail="Attachment content is empty")
    try:
        att = svc.store_attachment(
            filename=filename,
            raw_bytes=content.encode("utf-8", errors="replace"),
            content_type=str(body.get("content_type") or "text/plain"),
            conversation_id=conv_id,
        )
        return {"status": "ok", "attachment": att}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/chat/stream")
async def copilot_chat_stream(req: ChatStreamRequest):
    svc = _get_service()

    async def event_gen() -> AsyncGenerator[str, None]:
        try:
            async for event_name, payload in svc.stream_turn(
                message=req.message,
                conversation_id=req.conversation_id,
                engagement_id=req.engagement_id,
                run_id=req.run_id,
                model=req.model,
                mode=req.mode,
                attachment_ids=req.attachment_ids,
            ):
                yield _format_sse(event_name, payload)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Copilot stream error: %s", exc)
            yield _format_sse("error", {"error": str(exc)})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
