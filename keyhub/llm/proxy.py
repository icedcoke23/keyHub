"""LLM 代理转发。

流程：
1. balancer.pick(provider, model) 选 key
2. 用 vault 解出明文 api key
3. 按供应商配置构造上游请求
4. 转发并解析 usage
5. 记录用量；失败则标记 key 冷却并重试下一个 key
"""

from __future__ import annotations

import json
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


def _record_failed(
    key_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: int,
    err_msg: str,
    provider: str,
) -> None:
    """记录失败的 LLM 调用到 usage_logs（success=False）。

    成本按实际消耗 token 估算（多数失败无 token 消耗，cost=0）。
    provider 参数仅用于日志可读性，不参与估算。
    """
    try:
        record_usage(
            llm_key_id=key_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=estimate_cost(provider, model, prompt_tokens, completion_tokens),
            latency_ms=latency_ms,
            success=False,
            error=err_msg[:500] if err_msg else None,
        )
    except Exception as e:  # noqa: BLE001
        # 用量记录失败不应影响主流程
        print(f"[llm] failed to record usage: {e}", flush=True)


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
            raise LLMProxyError(f"no available key for provider='{provider}' model='{model}'") from None

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
        latency_ms = 0
        # 是否真正向上游发出了请求（用于决定是否记录 usage）
        request_sent = False

        try:
            with httpx.Client(timeout=settings.llm_timeout) as client:
                r = client.post(url, headers=headers, json=req_body)
            request_sent = True
            latency_ms = int((time.monotonic() - t0) * 1000)

            if r.status_code == 429:
                balancer.mark_rate_limited(key.id)
                err_msg = "rate_limited (429)"
                last_error = LLMProxyError(err_msg)
                # 部分上游在 429 时仍返回 usage，尽量解析
                try:
                    prompt_tokens, completion_tokens = _parse_usage(cfg, r.json())
                except Exception:
                    pass
                _record_failed(key.id, model, prompt_tokens, completion_tokens,
                               latency_ms, err_msg, provider)
                continue
            if r.status_code >= 400:
                balancer.mark_error(key.id)
                err_msg = f"upstream {r.status_code}: {r.text[:200]}"
                last_error = LLMProxyError(err_msg)
                _record_failed(key.id, model, 0, 0, latency_ms, err_msg, provider)
                continue

            resp_json = r.json()
            prompt_tokens, completion_tokens = _parse_usage(cfg, resp_json)
            success = True
        except (httpx.RequestError, ValueError) as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            balancer.mark_error(key.id)
            err_msg = str(e)
            last_error = e
            if request_sent:
                _record_failed(key.id, model, 0, 0, latency_ms, err_msg, provider)
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


# ===== 流式 =====

def chat_stream(
    provider: str,
    model: str,
    messages: list[dict[str, Any]],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
    extra: dict[str, Any] | None = None,
    max_retries: int = 3,
):
    """流式代理调用，生成 SSE 原始行（bytes）。

    上游响应体原样透传（OpenAI/Anthropic 均为 SSE 格式 `data: ...\n\n`），
    下游可直接转发。流结束后解析最后一个 chunk 的 usage 记录用量。
    """
    cfg = get_provider(provider)
    if not cfg.base_url:
        raise LLMProxyError(f"provider '{provider}' has no base_url configured")

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": True,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if extra:
        body.update(extra)

    balancer = get_balancer()
    settings = get_settings()
    from ..models import Credential, LLMKey
    from ..db import session_scope
    from sqlalchemy import select

    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            key = balancer.pick(provider, model)
        except NoAvailableKeyError:
            if last_error:
                raise LLMProxyError(f"all keys exhausted; last error: {last_error}") from last_error
            raise LLMProxyError(f"no available key for provider='{provider}' model='{model}'") from None

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
        prompt_tokens = completion_tokens = 0
        upstream_started = False
        try:
            with httpx.Client(timeout=settings.llm_timeout) as client:
                with client.stream("POST", url, headers=headers, json=req_body) as r:
                    if r.status_code == 429:
                        balancer.mark_rate_limited(key.id)
                        last_error = LLMProxyError("rate_limited (429)")
                        continue
                    if r.status_code >= 400:
                        balancer.mark_error(key.id)
                        last_error = LLMProxyError(f"upstream {r.status_code}")
                        continue
                    upstream_started = True
                    final_usage_chunk = None
                    for line in r.iter_lines():
                        if not line:
                            continue
                        # 解析 usage（OpenAI 在最后 chunk 含 usage；Anthropic 在 message_delta 事件含 usage）
                        s = line.strip() if isinstance(line, str) else line
                        if isinstance(s, bytes):
                            try:
                                s = s.decode("utf-8")
                            except Exception:
                                pass
                        if isinstance(s, str) and s.startswith("data:"):
                            payload = s[5:].strip()
                            if payload and payload != "[DONE]":
                                try:
                                    chunk_json = json.loads(payload)
                                    u = _extract_stream_usage(cfg, chunk_json)
                                    if u:
                                        prompt_tokens, completion_tokens = u
                                        final_usage_chunk = chunk_json
                                except Exception:
                                    pass
                        # 透传原始行
                        yield line if isinstance(line, bytes) else line.encode("utf-8")
                        yield b"\n"
            latency_ms = int((time.monotonic() - t0) * 1000)
            # 流结束，记录用量
            cost = estimate_cost(provider, model, prompt_tokens, completion_tokens)
            record_usage(
                llm_key_id=key.id, model=model,
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                cost_usd=cost, latency_ms=latency_ms, success=True, error=None,
            )
            balancer.mark_ok(key.id)
            return
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            balancer.mark_error(key.id)
            last_error = e
            if upstream_started:
                # 流已经开始则无法重试（下游已收到部分数据），记录失败并结束
                _record_failed(key.id, model, prompt_tokens, completion_tokens,
                               latency_ms, str(e), provider)
                raise LLMProxyError(f"stream interrupted: {e}") from e
            # 连接阶段失败：记录失败用量后重试下一个 key（与非流式 chat 一致）
            _record_failed(key.id, model, 0, 0, latency_ms, str(e), provider)
            continue

    if last_error:
        raise LLMProxyError(f"all retries failed; last error: {last_error}") from last_error
    raise LLMProxyError("stream failed for unknown reason")


def _extract_stream_usage(cfg, chunk_json: dict) -> tuple[int, int] | None:
    """从流式 chunk 提取 usage。返回 (prompt, completion) 或 None。"""
    if cfg.openai_compatible:
        u = chunk_json.get("usage")
        if u:
            return int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
        return None
    if cfg.name == "anthropic":
        # Anthropic: message_delta 事件的 usage 字段
        if chunk_json.get("type") == "message_delta":
            u = chunk_json.get("usage", {})
            # message_delta 的 usage 仅含 output_tokens；input_tokens 在 message_start
            return None, int(u.get("output_tokens", 0))
        if chunk_json.get("type") == "message_start":
            msg = chunk_json.get("message", {})
            u = msg.get("usage", {})
            return int(u.get("input_tokens", 0)), 0
        return None
    return None
