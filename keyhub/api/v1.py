"""OpenAI 兼容 API 路由。

提供与 OpenAI API 完全兼容的端点，让现有 OpenAI SDK 客户端零改动接入
KeyHub：只需把 base_url 指向 KeyHub 的 /v1 前缀，并以 KeyHub API Token
作为 Bearer 即可。

端点：
- POST /v1/chat/completions   聊天补全（支持流式与非流式）
- GET  /v1/models             聚合已配置 LLM Key 的可用模型列表
- POST /v1/embeddings         文本向量（直接转发上游 /v1/embeddings）

复用 keyhub.llm.proxy 的 chat / chat_stream 完成密钥选择、解密、上游转发、
用量记录与失败重试，本模块只负责协议适配与供应商推断。
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select

from ..audit import record as audit_record
from ..auth import require_scope
from ..config import get_settings
from ..db import session_scope
from ..llm.aliases import get_alias_manager
from ..llm.balancer import NoAvailableKeyError, get_balancer
from ..llm.proxy import LLMProxyError, _friendly_error, chat, chat_stream
from ..llm.providers import PRICING, get_provider
from ..models import AuditAction, Credential, LLMKey
from ..runtime import get_runtime

router = APIRouter(prefix="/v1", tags=["openai-compatible"])

logger = logging.getLogger(__name__)

# chat_stream 保留字段：这些字段会被显式提取并传给 chat()/chat_stream()，
# 不会进入 extra。其余 OpenAI 字段（tools / functions / tool_choice /
# top_p / frequency_penalty 等）通过 extra 原样透传给上游。
_CHAT_RESERVED_KEYS = {"model", "messages", "temperature", "max_tokens", "stream", "keyhub_provider"}

# 模型名前缀 → 供应商映射（顺序即匹配优先级）
_PROVIDER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("gpt-", "openai"),
    ("claude-", "anthropic"),
    ("deepseek-", "deepseek"),
    ("qwen-", "qwen"),
    ("glm-", "glm"),
    ("moonshot-", "moonshot"),
)


def infer_provider(model: str) -> str:
    """按模型名前缀推断供应商。无法匹配时默认 openai。"""
    if not model:
        return "openai"
    for prefix, provider in _PROVIDER_PREFIXES:
        if model.startswith(prefix):
            return provider
    return "openai"


def _openai_error(
    status_code: int,
    message: str,
    *,
    err_type: str = "internal_error",
    code: str | None = None,
) -> JSONResponse:
    """构造 OpenAI 风格的错误响应。"""
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": message, "type": err_type, "code": code}},
    )


@router.post("/chat/completions")
def chat_completions(body: dict[str, Any], actor: str = Depends(require_scope("llm:chat"))):
    """OpenAI 兼容的聊天补全端点。

    请求体为 OpenAI 格式 dict；可选 keyhub_provider 字段显式指定供应商，
    优先级高于按模型名前缀的推断。
    """
    model = body.get("model")
    if not model or not isinstance(model, str):
        return _openai_error(
            400,
            "you must provide a model parameter",
            err_type="invalid_request_error",
        )

    alias_mgr = get_alias_manager()
    explicit_provider = body.get("keyhub_provider")
    initial_provider = explicit_provider or infer_provider(model)
    provider, resolved_model = alias_mgr.resolve(initial_provider, model)
    model = resolved_model

    messages = body.get("messages") or []
    temperature = body.get("temperature")
    max_tokens = body.get("max_tokens")
    stream = bool(body.get("stream"))

    # 其余 OpenAI 字段通过 extra 透传给上游
    extra = {k: v for k, v in body.items() if k not in _CHAT_RESERVED_KEYS}
    if not extra:
        extra = None

    if stream:
        def _gen():
            try:
                yield from chat_stream(
                    provider=provider,
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    extra=extra,
                )
                yield b"data: [DONE]\n\n"
            except LLMProxyError as e:
                payload = {"error": {"message": str(e), "type": "upstream_error", "code": None}}
                yield f"data: {json.dumps(payload)}\n\n".encode("utf-8")
            except Exception:  # noqa: BLE001
                logger.exception("streaming chat internal error")
                payload = {"error": {"message": "internal error", "type": "internal_error", "code": None}}
                yield f"data: {json.dumps(payload)}\n\n".encode("utf-8")

        audit_record(
            AuditAction.llm_proxy_call,
            actor,
            target=provider,
            detail={"model": model, "stream": True, "endpoint": "/v1/chat/completions"},
        )
        return StreamingResponse(_gen(), media_type="text/event-stream")

    audit_record(
        AuditAction.llm_proxy_call,
        actor,
        target=provider,
        detail={"model": model, "stream": False, "endpoint": "/v1/chat/completions"},
    )
    try:
        return chat(
            provider=provider,
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
    except LLMProxyError as e:
        return _openai_error(502, str(e), err_type="upstream_error")
    except Exception:  # noqa: BLE001
        logger.exception("chat completions internal error")
        return _openai_error(500, "internal error", err_type="internal_error")


@router.get("/models")
def list_models(actor: str = Depends(require_scope("llm:read"))):
    """聚合已配置 LLM Key 的可用模型，返回 OpenAI 风格的列表。

    某 key 配置了 allowed_models → 列出这些模型；
    某 key allowed_models 为空 → 列出 PRICING 中该 provider 的所有模型。
    跨 key 去重（按模型 id）。
    """
    data: list[dict[str, str]] = []
    seen: set[str] = set()
    with session_scope() as s:
        rows = s.execute(select(LLMKey)).scalars().all()
        for k in rows:
            if k.allowed_models:
                candidates = list(k.allowed_models)
            else:
                candidates = list(PRICING.get(k.provider, {}).keys())
            for m in candidates:
                if m in seen:
                    continue
                seen.add(m)
                data.append({"id": m, "object": "model", "owned_by": k.provider})
    return {"object": "list", "data": data}


@router.post("/embeddings")
def embeddings(body: dict[str, Any], actor: str = Depends(require_scope("llm:chat"))):
    """OpenAI 兼容的文本向量端点。

    从 model 名推断 provider，选 key、解密后直接调用上游 /v1/embeddings，
    剔除 keyhub_provider 字段后透传请求体，上游响应原样返回。
    """
    model = body.get("model")
    if not model or not isinstance(model, str):
        return _openai_error(
            400,
            "you must provide a model parameter",
            err_type="invalid_request_error",
        )

    alias_mgr = get_alias_manager()
    explicit_provider = body.get("keyhub_provider")
    initial_provider = explicit_provider or infer_provider(model)
    provider, model = alias_mgr.resolve(initial_provider, model)

    settings = get_settings()
    balancer = get_balancer()

    audit_record(
        AuditAction.llm_proxy_call,
        actor,
        target=provider,
        detail={"model": model, "endpoint": "/v1/embeddings"},
    )

    try:
        try:
            cfg = get_provider(provider)
        except ValueError:
            return _openai_error(
                502, f"未知的供应商 '{provider}'", err_type="upstream_error",
            )
        if not cfg.base_url:
            return _openai_error(
                502,
                f"provider '{provider}' has no base_url configured",
                err_type="upstream_error",
            )

        try:
            key = balancer.pick(provider, model)
        except NoAvailableKeyError:
            if settings.llm_enable_cross_provider_fallback:
                try:
                    provider, key = balancer.pick_cross_provider(model, exclude_provider=initial_provider)
                    try:
                        cfg = get_provider(provider)
                    except ValueError:
                        balancer.release(key.id)
                        return _openai_error(
                            502, f"未知的供应商 '{provider}'", err_type="upstream_error",
                        )
                    if not cfg.base_url:
                        balancer.release(key.id)
                        return _openai_error(
                            502,
                            f"no available key for model='{model}'",
                            err_type="upstream_error",
                        )
                except NoAvailableKeyError:
                    return _openai_error(
                        502,
                        f"no available key for model='{model}'",
                        err_type="upstream_error",
                    )
            else:
                return _openai_error(
                    502,
                    f"no available key for provider='{provider}'",
                    err_type="upstream_error",
                )

        try:
            with session_scope() as s:
                row = s.execute(
                    select(LLMKey, Credential.encrypted_value, Credential.name)
                    .join(Credential, LLMKey.credential_id == Credential.id)
                    .where(LLMKey.id == key.id)
                ).one_or_none()
                if row is None:
                    balancer.mark_error(key.id)
                    return _openai_error(
                        502,
                        "selected key not found in database",
                        err_type="upstream_error",
                    )
                enc_value, cred_name = row[1], row[2]

            from ..llm.proxy import _decrypt_key
            api_key = _decrypt_key(key.id, enc_value, cred_name or key.id)

            req_body = {k: v for k, v in body.items() if k != "keyhub_provider"}
            req_body["model"] = model

            headers = {"Content-Type": "application/json"}
            if cfg.header_name:
                headers[cfg.header_name] = f"{cfg.header_prefix}{api_key}"
            if cfg.name == "anthropic":
                headers["anthropic-version"] = "2023-06-01"

            url = cfg.base_url.rstrip("/") + "/v1/embeddings"

            try:
                with httpx.Client(timeout=settings.llm_timeout) as client:
                    r = client.post(url, headers=headers, json=req_body)
            except httpx.RequestError as e:
                balancer.mark_error(key.id)
                logger.exception("embeddings upstream request failed")
                return _openai_error(502, _friendly_error(e), err_type="upstream_error")

            if r.status_code == 429:
                from ..llm.balancer import _parse_retry_after
                retry_after_val = _parse_retry_after(r.headers.get("Retry-After"))
                balancer.mark_rate_limited(key.id, retry_after=retry_after_val)
            elif r.status_code >= 400:
                balancer.mark_error(key.id)
            else:
                balancer.mark_ok(key.id)

            return Response(
                content=r.content,
                status_code=r.status_code,
                media_type=r.headers.get("content-type", "application/json"),
            )
        except Exception:
            balancer.release(key.id)
            raise
    except Exception:  # noqa: BLE001
        logger.exception("embeddings internal error")
        return _openai_error(500, "internal error", err_type="internal_error")
