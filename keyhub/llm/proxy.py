"""LLM 代理转发。

流程：
1. balancer.pick(provider, model) 选 key
2. 用 vault 解出明文 api key
3. 按供应商配置构造上游请求
4. 转发并解析 usage
5. 记录用量；失败则标记 key 冷却并重试下一个 key
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import get_settings
from ..runtime import get_runtime
from .balancer import NoAvailableKeyError, get_balancer
from .providers import estimate_cost, get_provider
from .tracker import record_usage


class LLMProxyError(RuntimeError):
    pass


def _decrypt_key(llm_key_id: str, credential_encrypted_value: bytes) -> str:
    return get_runtime().vault.decrypt(credential_encrypted_value)


def _build_request(
    cfg,
    api_key: str,
    body: dict[str, Any],
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """构造上游请求的 url / headers / body。"""
    headers = {"Content-Type": "application/json"}
    if cfg.header_name:
        headers[cfg.header_name] = f"{cfg.header_prefix}{api_key}"
    # Anthropic 额外需要 version 头
    if cfg.name == "anthropic":
        headers["anthropic-version"] = "2023-06-01"

    url = cfg.base_url.rstrip("/") + cfg.chat_path

    if cfg.openai_compatible:
        return url, headers, body

    # Anthropic 格式转换：OpenAI messages -> Anthropic messages
    if cfg.name == "anthropic":
        sys_msgs = [m["content"] for m in body.get("messages", []) if m.get("role") == "system"]
        user_msgs = [m for m in body.get("messages", []) if m.get("role") != "system"]
        anth_body = {
            "model": body.get("model"),
            "messages": user_msgs,
            "max_tokens": body.get("max_tokens", 1024),
        }
        if sys_msgs:
            anth_body["system"] = "\n\n".join(sys_msgs)
        if body.get("temperature") is not None:
            anth_body["temperature"] = body["temperature"]
        return url, headers, anth_body

    return url, headers, body


def _parse_usage(cfg, resp_json: dict[str, Any]) -> tuple[int, int]:
    """从响应解析 prompt/completion tokens。返回 (prompt, completion)。"""
    if cfg.openai_compatible:
        u = resp_json.get("usage", {}) or {}
        return int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
    if cfg.name == "anthropic":
        u = resp_json.get("usage", {}) or {}
        return int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))
    return 0, 0


def chat(
    provider: str,
    model: str,
    messages: list[dict[str, Any]],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
    extra: dict[str, Any] | None = None,
    max_retries: int = 3,
) -> dict[str, Any]:
    """同步代理调用，返回上游响应 JSON。"""
    cfg = get_provider(provider)
    if not cfg.base_url:
        raise LLMProxyError(f"provider '{provider}' has no base_url configured")

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if extra:
        body.update(extra)

    balancer = get_balancer()
    settings = get_settings()
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            key = balancer.pick(provider, model)
        except NoAvailableKeyError:
            if last_error:
                raise LLMProxyError(f"all keys exhausted; last error: {last_error}") from last_error
            raise

        # 取明文 key：需要关联的 credential.encrypted_value
        from ..models import Credential, LLMKey
        from ..db import session_scope
        from sqlalchemy import select

        with session_scope() as s:
            row = s.execute(
                select(LLMKey, Credential.encrypted_value)
                .join(Credential, LLMKey.credential_id == Credential.id)
                .where(LLMKey.id == key.id)
            ).one_or_none()
            if row is None:
                balancer.mark_error(key.id)
                continue
            llm_key, enc_value = row
            s.expunge(llm_key)

        api_key = _decrypt_key(llm_key.id, enc_value)
        url, headers, req_body = _build_request(cfg, api_key, body)

        t0 = time.monotonic()
        success = False
        err_msg: str | None = None
        prompt_tokens = completion_tokens = 0
        resp_json: dict[str, Any] = {}

        try:
            with httpx.Client(timeout=settings.llm_timeout) as client:
                r = client.post(url, headers=headers, json=req_body)
            latency_ms = int((time.monotonic() - t0) * 1000)

            if r.status_code == 429:
                balancer.mark_rate_limited(key.id)
                err_msg = f"rate_limited (429)"
                last_error = LLMProxyError(err_msg)
                continue
            if r.status_code >= 400:
                balancer.mark_error(key.id)
                err_msg = f"upstream {r.status_code}: {r.text[:200]}"
                last_error = LLMProxyError(err_msg)
                continue

            resp_json = r.json()
            prompt_tokens, completion_tokens = _parse_usage(cfg, resp_json)
            success = True
        except (httpx.RequestError, ValueError) as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            balancer.mark_error(key.id)
            err_msg = str(e)
            last_error = e
            continue

        # 成功：记录用量并返回
        cost = estimate_cost(provider, model, prompt_tokens, completion_tokens)
        record_usage(
            llm_key_id=key.id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            latency_ms=latency_ms,
            success=success,
            error=None,
        )
        balancer.mark_ok(key.id)
        return resp_json

    # 全部重试失败
    if last_error:
        raise LLMProxyError(f"all retries failed; last error: {last_error}") from last_error
    raise LLMProxyError("chat failed for unknown reason")
