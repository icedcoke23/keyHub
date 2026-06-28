"""OpenAI 兼容 API 路由。

提供与 OpenAI 官方接口一致的端点，使现有 OpenAI SDK 客户端可零改动接入 KeyHub：
- POST /v1/chat/completions  聊天补全（支持流式 / 非流式）
- GET  /v1/models            列出可用模型
- POST /v1/embeddings        向量嵌入代理

认证复用 KeyHub 的 require_auth（Bearer Token 或 Session Cookie），无需特定 scope。
底层聊天调用复用 /api/llm/chat 相同的 chat / chat_stream，因此 key 负载均衡、
冷却、用量记录等行为完全一致；本模块仅负责 OpenAI 协议适配与审计记录。
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select

from ..audit import record as audit_record
from ..auth import require_auth
from ..config import get_settings
from ..db import session_scope
from ..llm.balancer import NoAvailableKeyError, get_balancer
from ..llm.providers import PRICING, get_provider
from ..llm.proxy import LLMProxyError, chat, chat_stream
from ..models import AuditAction, Credential, LLMKey
from ..runtime import get_runtime

router = APIRouter(prefix="/v1", tags=["openai-compatible"])


# 模型名前缀 → 供应商 的推断规则（顺序敏感，按前缀匹配）
_MODEL_PREFIX_TO_PROVIDER = [
    ("gpt-", "openai"),
    ("claude-", "anthropic"),
    ("deepseek-", "deepseek"),
    ("qwen-", "qwen"),
    ("glm-", "glm"),
    ("moonshot-", "moonshot"),
]

# chat / chat_stream 会单独处理的字段；其余 OpenAI 字段（tools / functions /
# tool_choice / top_p / ...）一律透传给上游（通过 extra）。
_CHAT_RESERVED_KEYS = {
    "model", "messages", "temperature", "max_tokens", "stream", "keyhub_provider",
}


def infer_provider(model: str) -> str:
    """根据模型名推断供应商；未匹配时默认按 OpenAI 兼容处理。"""
    m = (model or "").lower()
    for prefix, provider in _MODEL_PREFIX_TO_PROVIDER:
        if m.startswith(prefix):
            return provider
    return "openai"


def _openai_error(
    status_code: int,
    message: str,
    *,
    err_type: str = "internal_error",
    code: str | None = None,
) -> JSONResponse:
    """构造 OpenAI 风格的错误响应：{"error": {"message", "type", "code"}}。"""
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": message, "type": err_type, "code": code}},
    )


# ===== Chat Completions =====


@router.post("/chat/completions")
def chat_completions(body: dict[str, Any] = Body(...), actor: str = Depends(require_auth)):
    """OpenAI 兼容的聊天补全端点。

    - model 名称自动推断 provider；请求体可选 keyhub_provider 显式覆盖
    - stream=true 返回 SSE 流式响应（与 /api/llm/chat 流式逻辑一致）
    - tools / functions / tool_choice 等额外参数透传给上游
    """
    model = body.get("model")
    if not model:
        return _openai_error(
            400, "必须提供 model 参数",
            err_type="invalid_request_error", code="model_required",
        )

    # keyhub_provider 显式指定供应商，优先于模型名推断
    keyhub_provider = body.get("keyhub_provider")
    provider = keyhub_provider or infer_provider(model)

    messages = body.get("messages") or []
    temperature = body.get("temperature")
    max_tokens = body.get("max_tokens")
    stream = bool(body.get("stream", False))

    # 其余 OpenAI 字段透传给上游
    extra = {k: v for k, v in body.items() if k not in _CHAT_RESERVED_KEYS}

    if stream:
        def _gen():
            try:
                yield from chat_stream(
                    provider=provider,
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    extra=extra or None,
                )
                yield b"data: [DONE]\n\n"
            except LLMProxyError as e:
                # 流式响应头已发出（HTTP 200），错误只能以 SSE 事件形式返回
                err = {"error": {"message": str(e), "type": "upstream_error", "code": "502"}}
                yield f"data: {json.dumps(err, ensure_ascii=False)}\n\n".encode("utf-8")

        audit_record(
            AuditAction.llm_proxy_call, actor,
            target=provider,
            detail={"model": model, "stream": True, "endpoint": "chat/completions"},
        )
        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        audit_record(
            AuditAction.llm_proxy_call, actor,
            target=provider,
            detail={"model": model, "stream": False, "endpoint": "chat/completions"},
        )
        return chat(
            provider=provider,
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra or None,
        )
    except LLMProxyError as e:
        return _openai_error(502, str(e), err_type="upstream_error", code="502")
    except Exception as e:  # noqa: BLE001
        return _openai_error(500, str(e), err_type="internal_error", code="internal_error")


# ===== Models =====


@router.get("/models")
def list_models(actor: str = Depends(require_auth)):
    """聚合已配置 LLM Key 的可用模型，返回 OpenAI 格式列表。

    - 某 key 显式配置了 allowed_models → 列出这些模型
    - 某 key 的 allowed_models 为空 → 列出该供应商的所有已知模型
      （PROVIDERS 本身不含模型清单，已知模型取自 PRICING 价格表的键名）
    """
    models: dict[str, str] = {}  # model_id -> provider(owned_by)
    with session_scope() as s:
        rows = s.execute(select(LLMKey)).scalars().all()
        for k in rows:
            if k.allowed_models:
                for m in k.allowed_models:
                    models[m] = k.provider
            else:
                for m in PRICING.get(k.provider, {}):
                    models[m] = k.provider

    data = [
        {"id": mid, "object": "model", "owned_by": prov}
        for mid, prov in sorted(models.items())
    ]
    return {"object": "list", "data": data}


# ===== Embeddings =====


@router.post("/embeddings")
def embeddings(body: dict[str, Any] = Body(...), actor: str = Depends(require_auth)):
    """OpenAI 兼容的向量嵌入代理。

    从模型名推断供应商，选取可用 key 解密后直接调用上游 /v1/embeddings，
    响应原样返回。仅记录审计日志，不估算 embedding 用量。
    """
    model = body.get("model")
    if not model:
        return _openai_error(
            400, "必须提供 model 参数",
            err_type="invalid_request_error", code="model_required",
        )

    keyhub_provider = body.get("keyhub_provider")
    provider = keyhub_provider or infer_provider(model)

    cfg = get_provider(provider)
    if not cfg.base_url:
        return _openai_error(
            502, f"供应商 '{provider}' 未配置 base_url",
            err_type="upstream_error", code="provider_not_configured",
        )

    balancer = get_balancer()
    try:
        key = balancer.pick(provider, model)
    except NoAvailableKeyError:
        return _openai_error(
            502, f"没有可用的 key（provider={provider}, model={model}）",
            err_type="upstream_error", code="no_available_key",
        )

    # 取明文 key（与 proxy.py 一致：关联 credential.encrypted_value 解密）
    with session_scope() as s:
        row = s.execute(
            select(LLMKey, Credential.encrypted_value)
            .join(Credential, LLMKey.credential_id == Credential.id)
            .where(LLMKey.id == key.id)
        ).one_or_none()
        if row is None:
            balancer.mark_error(key.id)
            return _openai_error(
                502, "所选 key 缺少关联凭证",
                err_type="upstream_error", code="key_missing",
            )
        enc_value = row[1]

    api_key = get_runtime().vault.decrypt(enc_value)

    # 构造上游请求头（与 proxy._build_request 的 header 逻辑一致）
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if cfg.header_name:
        headers[cfg.header_name] = f"{cfg.header_prefix}{api_key}"
    if cfg.name == "anthropic":
        headers["anthropic-version"] = "2023-06-01"

    # 剔除 KeyHub 专用字段后透传请求体
    upstream_body = {k: v for k, v in body.items() if k != "keyhub_provider"}
    url = cfg.base_url.rstrip("/") + "/v1/embeddings"

    audit_record(
        AuditAction.llm_proxy_call, actor,
        target=provider,
        detail={"model": model, "endpoint": "embeddings"},
    )

    settings = get_settings()
    try:
        with httpx.Client(timeout=settings.llm_timeout) as client:
            r = client.post(url, headers=headers, json=upstream_body)
    except httpx.RequestError as e:
        balancer.mark_error(key.id)
        return _openai_error(
            502, f"embeddings 上游请求失败：{e}",
            err_type="upstream_error", code="upstream_request_error",
        )

    if r.status_code == 429:
        balancer.mark_rate_limited(key.id)
        return _openai_error(
            429, "embeddings 上游限流（429）",
            err_type="rate_limit_error", code="429",
        )
    if r.status_code >= 400:
        balancer.mark_error(key.id)
        return _openai_error(
            502, f"upstream {r.status_code}: {r.text[:200]}",
            err_type="upstream_error", code=str(r.status_code),
        )

    balancer.mark_ok(key.id)
    try:
        return r.json()
    except ValueError:
        return _openai_error(
            502, "上游返回非 JSON 响应",
            err_type="upstream_error", code="bad_upstream_response",
        )
