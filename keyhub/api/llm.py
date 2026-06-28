"""LLM 路由：代理调用、用量查询、key 状态管理。"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from ..audit import record as audit_record
from ..auth import require_auth
from ..llm.balancer import get_balancer
from ..llm.proxy import LLMProxyError, chat, chat_stream
from ..llm.tracker import aggregate_cost, list_llm_keys, list_usage
from ..models import AuditAction, LLMKeyStatus
from ..schemas import LLMChatRequest, LLMKeySummary, MessageOut, UsageOut

router = APIRouter(prefix="/api/llm", tags=["llm"])


@router.post("/chat")
def chat_endpoint(body: LLMChatRequest, actor: str = Depends(require_auth)):
    """通过 KeyHub 代理调用 LLM（非流式）。下游无需接触真实 key。"""
    if body.stream:
        # 流式：返回 SSE 透传
        def _gen():
            try:
                yield from chat_stream(
                    provider=body.provider,
                    model=body.model,
                    messages=body.messages,
                    temperature=body.temperature,
                    max_tokens=body.max_tokens,
                    extra=body.extra or None,
                )
                yield b"data: [DONE]\n\n"
            except LLMProxyError as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n".encode("utf-8")

        audit_record(AuditAction.llm_proxy_call, actor,
                     target=body.provider, detail={"model": body.model, "stream": True})
        return StreamingResponse(_gen(), media_type="text/event-stream")
    try:
        audit_record(AuditAction.llm_proxy_call, actor,
                     target=body.provider, detail={"model": body.model, "stream": False})
        return chat(
            provider=body.provider,
            model=body.model,
            messages=body.messages,
            temperature=body.temperature,
            max_tokens=body.max_tokens,
            extra=body.extra or None,
        )
    except LLMProxyError as e:
        raise HTTPException(502, str(e))


@router.get("/keys", response_model=list[LLMKeySummary])
def list_keys(
    provider: str | None = Query(None),
    _: str = Depends(require_auth),
):
    return list_llm_keys(provider=provider)


@router.patch("/keys/{key_id}/status", response_model=MessageOut)
def set_key_status(
    key_id: str,
    status: LLMKeyStatus = Query(...),
    _: str = Depends(require_auth),
):
    """手动启用/停用某个 key。"""
    get_balancer()
    from ..db import session_scope
    from ..models import LLMKey
    with session_scope() as s:
        k = s.get(LLMKey, key_id)
        if k is None:
            raise HTTPException(404, "key not found")
        k.status = status
        if status == LLMKeyStatus.active:
            k.cooldown_until = None
    return MessageOut(message=f"status set to {status}")


@router.get("/usage", response_model=list[UsageOut])
def usage(
    limit: int = Query(100, le=1000),
    provider: str | None = Query(None),
    _: str = Depends(require_auth),
):
    return list_usage(limit=limit, provider=provider)


@router.get("/cost")
def cost(provider: str | None = Query(None), _: str = Depends(require_auth)):
    return aggregate_cost(provider=provider)
