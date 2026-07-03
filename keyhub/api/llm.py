"""LLM 路由：代理调用、用量查询、key 状态管理。"""

from __future__ import annotations

import json
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from sqlalchemy import select

from ..audit import record as audit_record
from ..auth import require_auth, require_scope
from ..config import get_settings
from ..db import session_scope
from ..llm.balancer import get_balancer
from ..llm.providers import get_provider
from ..llm.proxy import LLMProxyError, _decrypt_key, chat, chat_stream
from ..llm.tracker import aggregate_cost, list_llm_keys, list_usage
from ..models import AuditAction, Credential, LLMKey, LLMKeyStatus
from ..schemas import LLMChatRequest, LLMKeySummary, MessageOut, UsageOut

router = APIRouter(prefix="/api/llm", tags=["llm"])


@router.post("/chat")
def chat_endpoint(body: LLMChatRequest, actor: str = Depends(require_scope("llm:chat"))):
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
    _: str = Depends(require_scope("llm:read")),
):
    return list_llm_keys(provider=provider)


@router.patch("/keys/{key_id}/status", response_model=MessageOut)
def set_key_status(
    key_id: str,
    status: LLMKeyStatus = Query(...),
    _: str = Depends(require_scope("llm:write")),
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
    _: str = Depends(require_scope("llm:read")),
):
    return list_usage(limit=limit, provider=provider)


@router.get("/cost")
def cost(provider: str | None = Query(None), _: str = Depends(require_scope("llm:read"))):
    return aggregate_cost(provider=provider)


@router.get("/cost/trend")
def cost_trend(
    days: int = Query(7, ge=1, le=90),
    provider: str | None = Query(None),
    _: str = Depends(require_scope("llm:read")),
):
    """按天聚合成本趋势。"""
    from datetime import datetime, timedelta
    from sqlalchemy import func, cast, Date
    from ..db import session_scope
    from ..models import UsageLog
    cutoff = datetime.utcnow() - timedelta(days=days)
    with session_scope() as s:
        stmt = (
            select(
                cast(UsageLog.created_at, Date).label("day"),
                func.sum(UsageLog.cost_usd).label("cost"),
                func.count(UsageLog.id).label("calls"),
            )
            .where(UsageLog.created_at >= cutoff)
            .group_by("day")
            .order_by("day")
        )
        if provider:
            stmt = stmt.join(LLMKey, UsageLog.llm_key_id == LLMKey.id).where(LLMKey.provider == provider)
        rows = s.execute(stmt).all()
    return [
        {"date": str(r.day), "cost": round(r.cost or 0, 6), "calls": int(r.calls or 0)}
        for r in rows
    ]


@router.get("/latency")
def latency_stats(_: str = Depends(require_scope("llm:read"))):
    """返回各 provider 的延迟分位数（P50/P95/P99）。"""
    from ..llm.latency_stats import get_latency_stats
    return get_latency_stats().all_providers()


@router.get("/cache/stats")
def cache_stats(_: str = Depends(require_scope("llm:read"))):
    """响应缓存统计。"""
    from ..llm.cache import get_cache
    return get_cache().stats()


@router.post("/cache/clear", response_model=MessageOut)
def cache_clear(_: str = Depends(require_scope("llm:write"))):
    """清空响应缓存。"""
    from ..llm.cache import get_cache
    n = get_cache().clear()
    return MessageOut(message=f"cleared {n} cache entries")


@router.post("/keys/{key_id}/test")
def test_key(
    key_id: str,
    _: str = Depends(require_scope("llm:read")),
):
    """测试指定 Key 的连通性：解密后请求上游 models 端点，测量延迟。"""
    settings = get_settings()
    balancer = get_balancer()

    with session_scope() as s:
        row = s.execute(
            select(LLMKey, Credential.encrypted_value, Credential.name)
            .join(Credential, LLMKey.credential_id == Credential.id)
            .where(LLMKey.id == key_id)
        ).one_or_none()
        if row is None:
            raise HTTPException(404, "key not found")
        llm_key, enc_value, cred_name = row
        provider_name = llm_key.provider
        s.expunge(llm_key)

    cfg = get_provider(provider_name)
    if not cfg.base_url:
        return {"success": False, "latency_ms": 0, "error": f"provider '{provider_name}' has no base_url configured", "models": None}

    api_key = _decrypt_key(llm_key.id, enc_value, cred_name or key_id)

    headers = {"Content-Type": "application/json"}
    if cfg.header_name:
        headers[cfg.header_name] = f"{cfg.header_prefix}{api_key}"
    if cfg.name == "anthropic":
        headers["anthropic-version"] = "2023-06-01"

    if cfg.openai_compatible:
        test_url = cfg.base_url.rstrip("/") + "/v1/models"
    else:
        test_url = cfg.base_url.rstrip("/") + "/v1/models"

    t0 = time.monotonic()
    latency_ms = 0
    models: list | None = None
    error_msg: str | None = None
    success = False

    try:
        timeout = httpx.Timeout(
            connect=settings.llm_connect_timeout,
            read=settings.llm_read_timeout,
            write=settings.llm_connect_timeout,
            pool=settings.llm_connect_timeout,
        )
        with httpx.Client(timeout=timeout) as client:
            r = client.get(test_url, headers=headers)
        latency_ms = int((time.monotonic() - t0) * 1000)

        if r.status_code >= 400:
            # 不回传上游响应体（可能含 key 回显/内部细节），仅暴露状态码
            error_msg = f"upstream returned {r.status_code}"
        else:
            try:
                resp_json = r.json()
                if cfg.openai_compatible:
                    data = resp_json.get("data", [])
                    models = [m.get("id", str(m)) if isinstance(m, dict) else str(m) for m in data]
                else:
                    models = []
            except Exception:
                models = []
            success = True
    except (httpx.RequestError, ValueError) as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        # ValueError（如 JSON 解析）消息受控可回传；httpx.RequestError
        # 可能含内部主机名/URL，统一转为通用网络错误提示
        if isinstance(e, ValueError):
            error_msg = str(e)
        else:
            error_msg = "network error: failed to reach upstream"

    if success:
        balancer.mark_ok(key_id, latency_ms)
    else:
        balancer.mark_error(key_id)

    return {
        "success": success,
        "latency_ms": latency_ms,
        "error": error_msg,
        "models": models,
    }
