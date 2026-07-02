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
import random
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from ..config import get_settings
from ..runtime import get_runtime
from .aliases import get_alias_manager
from .balancer import NoAvailableKeyError, _parse_retry_after, get_balancer
from .providers import estimate_cost, get_provider
from .tracker import record_usage

_semaphore: Optional[threading.Semaphore] = None
_semaphore_lock = threading.Lock()


def _get_semaphore() -> Optional[threading.Semaphore]:
    """获取全局并发信号量（懒加载，0 表示不限）。"""
    global _semaphore
    with _semaphore_lock:
        if _semaphore is not None:
            return _semaphore
        settings = get_settings()
        max_conc = settings.llm_max_concurrent
        if max_conc and max_conc > 0:
            _semaphore = threading.Semaphore(max_conc)
        else:
            _semaphore = None
        return _semaphore


class LLMProxyError(RuntimeError):
    pass


def _backoff_wait(attempt: int) -> None:
    """指数退避+抖动。
    - attempt=0（首次尝试）: 不等待
    - attempt=1（第一次重试，第一个 key 失败后）: 不等待，直接切换
    - attempt>=2（第二次重试起）: wait = min(max_ms, base_ms*2^attempt) + random.uniform(0, base_ms)
    """
    if attempt < 2:
        return
    base_ms = 200
    max_ms = 5000
    wait_ms = min(max_ms, base_ms * (2 ** attempt))
    jitter = random.uniform(0, base_ms)
    total_s = (wait_ms + jitter) / 1000.0
    try:
        time.sleep(total_s)
    except Exception:
        pass


def _friendly_error(err: Exception | str) -> str:
    """将底层异常转换为用户友好的中文提示，隐藏原始堆栈/SSL 细节。"""
    msg = str(err)

    if "UNEXPECTED_EOF" in msg or "EOF in violation" in msg:
        return "上游连接异常断开，请检查网络或 LLM 服务可用性"
    if "SSLError" in msg or "ssl" in msg.lower():
        return "SSL 握手失败，可能是网络代理或上游证书问题"
    if "ConnectError" in msg or "ConnectionRefused" in msg:
        return "无法连接到 LLM 上游服务，请检查网络"
    if "timeout" in msg.lower() or "timed out" in msg.lower():
        return "LLM 调用超时，请稍后重试或调整超时设置"
    if "ConnectTimeout" in msg or "ReadTimeout" in msg:
        return "LLM 调用超时，请稍后重试或调整超时设置"

    if "rate_limited" in msg or "429" in msg:
        return "LLM 上游限流（429），请稍后重试"

    if "401" in msg or "Unauthorized" in msg:
        return "LLM API Key 无效或已失效（401），请检查 key"
    if "403" in msg or "Forbidden" in msg:
        return "LLM API Key 无权限（403），请检查 key 配置"

    if "all keys exhausted" in msg or "all retries failed" in msg:
        return "所有可用 key 已耗尽或全部失败，请检查 key 状态与网络"

    if "upstream 5" in msg:
        return "LLM 上游服务异常（5xx），请稍后重试"
    if "upstream 4" in msg:
        return "LLM 上游拒绝请求（4xx），请检查模型名与参数"

    if len(msg) > 120:
        return msg[:120] + "…"
    return msg


def _decrypt_key(llm_key_id: str, credential_encrypted_value: bytes, cred_name: str = "") -> str:
    from ..store import reveal_raw
    return reveal_raw(llm_key_id, credential_encrypted_value, cred_name)


def _record_failed(
    key_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: int,
    err_msg: str,
    provider: str,
) -> None:
    """记录失败的 LLM 调用到 usage_logs（success=False）。"""
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
    except Exception as e:
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
    if cfg.name == "anthropic":
        headers["anthropic-version"] = "2023-06-01"

    url = cfg.base_url.rstrip("/") + cfg.chat_path

    if cfg.openai_compatible:
        return url, headers, body

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


def _acquire_semaphore(timeout: float) -> bool:
    """尝试获取并发信号量，返回是否成功。"""
    sem = _get_semaphore()
    if sem is None:
        return True
    try:
        return sem.acquire(timeout=timeout)
    except Exception:
        return True


def _release_semaphore() -> None:
    sem = _get_semaphore()
    if sem is not None:
        try:
            sem.release()
        except Exception:
            pass


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
    alias_mgr = get_alias_manager()
    provider, model = alias_mgr.resolve(provider, model)

    cfg = get_provider(provider)
    if not cfg.base_url:
        raise LLMProxyError(f"provider '{provider}' has no base_url configured")

    settings = get_settings()
    from .cache import get_cache
    cache = get_cache()
    cached = cache.get(provider, model, messages, temperature, settings.llm_cache_ttl)
    if cached is not None:
        try:
            from ..metrics import llm_cache_hits
            llm_cache_hits.inc()
        except Exception:
            pass
        return cached
    try:
        from ..metrics import llm_cache_misses
        llm_cache_misses.inc()
    except Exception:
        pass

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
    last_error: Exception | None = None
    current_provider = provider
    current_cfg = cfg
    fallback_tried = False

    for attempt in range(max_retries):
        if attempt > 0:
            _backoff_wait(attempt)

        if not _acquire_semaphore(settings.llm_connect_timeout):
            last_error = LLMProxyError("LLM 并发请求数已达上限，请稍后重试")
            continue

        try:
            key = balancer.pick(current_provider, model)
        except NoAvailableKeyError:
            _release_semaphore()
            if settings.llm_enable_cross_provider_fallback and not fallback_tried:
                fallback_tried = True
                try:
                    fallback_provider, fallback_key = balancer.pick_cross_provider(model, exclude_provider=provider)
                    current_provider = fallback_provider
                    current_cfg = get_provider(current_provider)
                    key = fallback_key
                except NoAvailableKeyError:
                    try:
                        from ..metrics import llm_requests_total
                        llm_requests_total.labels(provider=provider, model=model, status="fail").inc()
                    except Exception:
                        pass
                    if last_error:
                        raise LLMProxyError(_friendly_error(last_error)) from last_error
                    raise LLMProxyError(f"没有可用的 key（provider={provider}, model={model}），请在控制台添加") from None
            else:
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=provider, model=model, status="fail").inc()
                except Exception:
                    pass
                if last_error:
                    raise LLMProxyError(_friendly_error(last_error)) from last_error
                raise LLMProxyError(f"没有可用的 key（provider={provider}, model={model}），请在控制台添加") from None

        if key.monthly_budget_usd > 0 and key.estimated_cost_usd >= key.monthly_budget_usd:
            _check_budget_exceeded(key.id, key.estimated_cost_usd, key.monthly_budget_usd, current_provider)
            balancer.release(key.id)
            _release_semaphore()
            continue

        from ..models import Credential, LLMKey
        from ..db import session_scope
        from sqlalchemy import select

        with session_scope() as s:
            row = s.execute(
                select(LLMKey, Credential.encrypted_value, Credential.name)
                .join(Credential, LLMKey.credential_id == Credential.id)
                .where(LLMKey.id == key.id)
            ).one_or_none()
            if row is None:
                balancer.mark_error(key.id)
                _release_semaphore()
                continue
            llm_key, enc_value, cred_name = row
            s.expunge(llm_key)

        try:
            from .keylimit import get_key_rate_limiter
            limiter = get_key_rate_limiter()
            allowed, _, _ = limiter.check(key.id, tokens=0)
            if not allowed:
                balancer.mark_rate_limited(key.id, retry_after=10.0)
                last_error = LLMProxyError("key rate limit exceeded")
                _release_semaphore()
                continue
        except Exception:
            pass

        api_key = _decrypt_key(llm_key.id, enc_value, cred_name or key.id)
        url, headers, req_body = _build_request(current_cfg, api_key, body)

        t0 = time.monotonic()
        success = False
        err_msg: str | None = None
        prompt_tokens = completion_tokens = 0
        resp_json: dict[str, Any] = {}
        latency_ms = 0
        request_sent = False

        try:
            timeout = httpx.Timeout(
                connect=settings.llm_connect_timeout,
                read=settings.llm_read_timeout,
                write=settings.llm_connect_timeout,
                pool=settings.llm_connect_timeout,
            )
            with httpx.Client(timeout=timeout) as client:
                r = client.post(url, headers=headers, json=req_body)
            request_sent = True
            latency_ms = int((time.monotonic() - t0) * 1000)

            if r.status_code == 429:
                retry_after_val = _parse_retry_after(r.headers.get("Retry-After"))
                balancer.mark_rate_limited(key.id, retry_after=retry_after_val)
                err_msg = "rate_limited (429)"
                last_error = LLMProxyError(err_msg)
                try:
                    prompt_tokens, completion_tokens = _parse_usage(current_cfg, r.json())
                except Exception:
                    pass
                _record_failed(key.id, model, prompt_tokens, completion_tokens,
                               latency_ms, err_msg, current_provider)
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=current_provider, model=model, status="fail").inc()
                except Exception:
                    pass
                _release_semaphore()
                continue
            if r.status_code >= 400:
                balancer.mark_error(key.id)
                err_msg = f"upstream {r.status_code}: {r.text[:200]}"
                last_error = LLMProxyError(err_msg)
                _record_failed(key.id, model, 0, 0, latency_ms, err_msg, current_provider)
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=current_provider, model=model, status="fail").inc()
                except Exception:
                    pass
                _release_semaphore()
                continue

            resp_json = r.json()
            prompt_tokens, completion_tokens = _parse_usage(current_cfg, resp_json)
            success = True
        except (httpx.RequestError, ValueError) as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            balancer.mark_error(key.id)
            err_msg = str(e)
            last_error = e
            if request_sent:
                _record_failed(key.id, model, 0, 0, latency_ms, err_msg, current_provider)
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=current_provider, model=model, status="fail").inc()
                except Exception:
                    pass
            _release_semaphore()
            continue

        total_tokens = prompt_tokens + completion_tokens
        try:
            from .keylimit import get_key_rate_limiter
            get_key_rate_limiter().record(key.id, tokens=total_tokens)
        except Exception:
            pass

        cost = estimate_cost(current_provider, model, prompt_tokens, completion_tokens)
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
        balancer.mark_ok(key.id, latency_ms)
        try:
            from ..metrics import llm_request_duration, llm_cost_total, llm_tokens_total, llm_requests_total
            llm_requests_total.labels(provider=current_provider, model=model, status="ok").inc()
            llm_request_duration.labels(provider=current_provider, model=model).observe(latency_ms / 1000)
            llm_cost_total.labels(provider=current_provider, model=model).inc(cost)
            llm_tokens_total.labels(provider=current_provider, model=model, kind="prompt").inc(prompt_tokens)
            llm_tokens_total.labels(provider=current_provider, model=model, kind="completion").inc(completion_tokens)
        except Exception:
            pass
        try:
            from .latency_stats import get_latency_stats
            get_latency_stats().record(current_provider, latency_ms)
        except Exception:
            pass
        cache.set(current_provider, model, messages, temperature, resp_json)
        _release_semaphore()
        return resp_json

    if last_error:
        raise LLMProxyError(_friendly_error(last_error)) from last_error
    raise LLMProxyError("调用失败，原因未知")


# ===== 流式 =====

def _make_sse_error(message: str) -> bytes:
    """构造 SSE 错误事件。"""
    payload = json.dumps({"error": {"message": message, "type": "stream_error"}})
    return f"data: {payload}\n\n".encode("utf-8")


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
    """流式代理调用，生成 SSE 原始行（bytes）。"""
    alias_mgr = get_alias_manager()
    provider, model = alias_mgr.resolve(provider, model)

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
    current_provider = provider
    current_cfg = cfg
    fallback_tried = False

    for attempt in range(max_retries):
        if attempt > 0:
            _backoff_wait(attempt)

        sem_held = False
        upstream_started = False
        key = None
        t0 = time.monotonic()
        prompt_tokens = completion_tokens = 0

        if not _acquire_semaphore(settings.llm_connect_timeout):
            last_error = LLMProxyError("LLM 并发请求数已达上限，请稍后重试")
            continue
        sem_held = True

        def _cleanup():
            nonlocal sem_held
            if sem_held:
                _release_semaphore()
                sem_held = False

        try:
            try:
                key = balancer.pick(current_provider, model)
            except NoAvailableKeyError:
                if settings.llm_enable_cross_provider_fallback and not fallback_tried:
                    fallback_tried = True
                    try:
                        fallback_provider, fallback_key = balancer.pick_cross_provider(model, exclude_provider=provider)
                        current_provider = fallback_provider
                        current_cfg = get_provider(current_provider)
                        key = fallback_key
                    except NoAvailableKeyError:
                        _cleanup()
                        try:
                            from ..metrics import llm_requests_total
                            llm_requests_total.labels(provider=provider, model=model, status="fail").inc()
                        except Exception:
                            pass
                        if last_error:
                            raise LLMProxyError(_friendly_error(last_error)) from last_error
                        raise LLMProxyError(f"没有可用的 key（provider={provider}, model={model}），请在控制台添加") from None
                else:
                    _cleanup()
                    try:
                        from ..metrics import llm_requests_total
                        llm_requests_total.labels(provider=provider, model=model, status="fail").inc()
                    except Exception:
                        pass
                    if last_error:
                        raise LLMProxyError(_friendly_error(last_error)) from last_error
                    raise LLMProxyError(f"没有可用的 key（provider={provider}, model={model}），请在控制台添加") from None

            if key.monthly_budget_usd > 0 and key.estimated_cost_usd >= key.monthly_budget_usd:
                _check_budget_exceeded(key.id, key.estimated_cost_usd, key.monthly_budget_usd, current_provider)
                balancer.release(key.id)
                _cleanup()
                continue

            with session_scope() as s:
                row = s.execute(
                    select(LLMKey, Credential.encrypted_value, Credential.name)
                    .join(Credential, LLMKey.credential_id == Credential.id)
                    .where(LLMKey.id == key.id)
                ).one_or_none()
                if row is None:
                    balancer.mark_error(key.id)
                    _cleanup()
                    continue
                llm_key, enc_value, cred_name = row
                s.expunge(llm_key)

            try:
                from .keylimit import get_key_rate_limiter
                limiter = get_key_rate_limiter()
                allowed, _, _ = limiter.check(key.id, tokens=0)
                if not allowed:
                    balancer.mark_rate_limited(key.id, retry_after=10.0)
                    last_error = LLMProxyError("key rate limit exceeded")
                    _cleanup()
                    continue
            except Exception:
                pass

            api_key = _decrypt_key(llm_key.id, enc_value, cred_name or key.id)
            url, headers, req_body = _build_request(current_cfg, api_key, body)

            t0 = time.monotonic()
            prompt_tokens = completion_tokens = 0
            stream_error: str | None = None

            timeout = httpx.Timeout(
                connect=settings.llm_connect_timeout,
                read=settings.llm_read_timeout,
                write=settings.llm_connect_timeout,
                pool=settings.llm_connect_timeout,
            )
            with httpx.Client(timeout=timeout) as client:
                with client.stream("POST", url, headers=headers, json=req_body) as r:
                    if r.status_code == 429:
                        retry_after_val = _parse_retry_after(r.headers.get("Retry-After"))
                        balancer.mark_rate_limited(key.id, retry_after=retry_after_val)
                        last_error = LLMProxyError("rate_limited (429)")
                        _cleanup()
                        continue
                    if r.status_code >= 400:
                        balancer.mark_error(key.id)
                        err_text = ""
                        try:
                            err_text = r.text[:200]
                        except Exception:
                            pass
                        last_error = LLMProxyError(f"upstream {r.status_code}: {err_text}")
                        _cleanup()
                        continue
                    upstream_started = True
                    last_data_time = time.monotonic()
                    idle_timeout = settings.llm_read_timeout

                    for line in r.iter_lines():
                        now = time.monotonic()
                        if now - last_data_time > idle_timeout:
                            stream_error = f"流式读取超时（{idle_timeout}秒无数据）"
                            yield _make_sse_error(_friendly_error(stream_error))
                            break
                        last_data_time = now

                        if not line:
                            continue
                        s_line = line.strip() if isinstance(line, str) else line
                        if isinstance(s_line, bytes):
                            try:
                                s_line = s_line.decode("utf-8")
                            except Exception:
                                pass
                        if isinstance(s_line, str) and s_line.startswith("data:"):
                            payload = s_line[5:].strip()
                            if payload and payload != "[DONE]":
                                try:
                                    chunk_json = json.loads(payload)
                                    if "error" in chunk_json and isinstance(chunk_json["error"], dict):
                                        err_msg = chunk_json["error"].get("message", "上游返回错误")
                                        stream_error = err_msg
                                        yield _make_sse_error(_friendly_error(err_msg))
                                        break
                                    if chunk_json.get("error") and isinstance(chunk_json["error"], str):
                                        stream_error = chunk_json["error"]
                                        yield _make_sse_error(_friendly_error(stream_error))
                                        break
                                    u = _extract_stream_usage(current_cfg, chunk_json)
                                    if u:
                                        prompt_tokens, completion_tokens = u
                                except json.JSONDecodeError:
                                    pass
                                except Exception:
                                    pass
                        if stream_error:
                            break
                        yield line if isinstance(line, bytes) else line.encode("utf-8")
                        yield b"\n"

            latency_ms = int((time.monotonic() - t0) * 1000)

            if stream_error:
                balancer.mark_error(key.id)
                _record_failed(key.id, model, prompt_tokens, completion_tokens,
                               latency_ms, stream_error, current_provider)
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=current_provider, model=model, status="fail").inc()
                except Exception:
                    pass
                _cleanup()
                return

            total_tokens = prompt_tokens + completion_tokens
            try:
                from .keylimit import get_key_rate_limiter
                get_key_rate_limiter().record(key.id, tokens=total_tokens)
            except Exception:
                pass
            cost = estimate_cost(current_provider, model, prompt_tokens, completion_tokens)
            record_usage(
                llm_key_id=key.id, model=model,
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                cost_usd=cost, latency_ms=latency_ms, success=True, error=None,
            )
            balancer.mark_ok(key.id)
            try:
                from ..metrics import llm_request_duration, llm_cost_total, llm_tokens_total, llm_requests_total
                llm_requests_total.labels(provider=current_provider, model=model, status="ok").inc()
                llm_request_duration.labels(provider=current_provider, model=model).observe(latency_ms / 1000)
                llm_cost_total.labels(provider=current_provider, model=model).inc(cost)
                llm_tokens_total.labels(provider=current_provider, model=model, kind="prompt").inc(prompt_tokens)
                llm_tokens_total.labels(provider=current_provider, model=model, kind="completion").inc(completion_tokens)
            except Exception:
                pass
            try:
                from .latency_stats import get_latency_stats
                get_latency_stats().record(current_provider, latency_ms)
            except Exception:
                pass
            _cleanup()
            return
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            if key:
                balancer.mark_error(key.id)
            last_error = e
            if upstream_started:
                if key:
                    _record_failed(key.id, model, prompt_tokens, completion_tokens,
                                   latency_ms, str(e), current_provider)
                try:
                    from ..metrics import llm_requests_total
                    llm_requests_total.labels(provider=current_provider, model=model, status="fail").inc()
                except Exception:
                    pass
                yield _make_sse_error(_friendly_error(e))
                _cleanup()
                return
            if key:
                _record_failed(key.id, model, 0, 0, latency_ms, str(e), current_provider)
            _cleanup()
            continue
        except GeneratorExit:
            latency_ms = int((time.monotonic() - t0) * 1000)
            if key and upstream_started:
                _record_failed(key.id, model, prompt_tokens, completion_tokens,
                               latency_ms, "client disconnected", current_provider)
                balancer.mark_error(key.id)
            elif key:
                balancer.release(key.id)
            _cleanup()
            raise
        except Exception as e:
            latency_ms = int((time.monotonic() - t0) * 1000)
            if key:
                balancer.mark_error(key.id)
                if upstream_started:
                    _record_failed(key.id, model, prompt_tokens, completion_tokens,
                                   latency_ms, str(e), current_provider)
                    yield _make_sse_error(_friendly_error(e))
                    _cleanup()
                    return
                _record_failed(key.id, model, 0, 0, latency_ms, str(e), current_provider)
            _cleanup()
            last_error = e
            continue

    if last_error:
        raise LLMProxyError(_friendly_error(last_error)) from last_error
    raise LLMProxyError("流式调用失败，原因未知")


def _extract_stream_usage(cfg, chunk_json: dict) -> tuple[int, int] | None:
    """从流式 chunk 提取 usage。返回 (prompt, completion) 或 None。"""
    if cfg.openai_compatible:
        u = chunk_json.get("usage")
        if u:
            return int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
        return None
    if cfg.name == "anthropic":
        if chunk_json.get("type") == "message_delta":
            u = chunk_json.get("usage", {})
            return None, int(u.get("output_tokens", 0))
        if chunk_json.get("type") == "message_start":
            msg = chunk_json.get("message", {})
            u = msg.get("usage", {})
            return int(u.get("input_tokens", 0)), 0
        return None
    return None


def _check_budget_exceeded(key_id, cost, budget, provider):
    """预算超限：停用 key + 审计 + 通知。"""
    from sqlalchemy import update
    from ..models import LLMKey, LLMKeyStatus, AuditAction
    from ..audit import record as audit_record
    from ..notify import get_notifier
    from ..db import session_scope
    with session_scope() as s:
        s.execute(update(LLMKey).where(LLMKey.id == key_id).values(
            status=LLMKeyStatus.exhausted, cooldown_until=None
        ))
    audit_record(AuditAction.llm_budget_exceeded, "system",
                 target=f"key:{key_id}",
                 detail={"cost": cost, "budget": budget, "provider": provider})
    try:
        get_notifier().notify("llm.budget_exceeded", {
            "key_id": key_id, "provider": provider, "cost": cost, "budget": budget
        })
    except Exception:
        pass
