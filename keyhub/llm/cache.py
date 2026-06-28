"""LLM 响应缓存。

对非流式 chat 请求做 prompt hash 缓存，相同 (provider, model, messages, temperature)
在 TTL 内直接返回缓存结果，节约成本。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any


class ResponseCache:
    """内存 LRU + TTL 缓存（单例）。

    缓存键：sha256(provider + model + messages_json + temperature) 的前 16 位 hex。
    缓存值：上游响应 JSON dict + 时间戳。
    过期条目在 get 时惰性清理。
    """

    _instance: "ResponseCache | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "ResponseCache":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._store: dict[str, tuple[float, dict]] = {}  # type: ignore
                cls._instance._max_size = 256  # type: ignore
            return cls._instance

    def _make_key(
        self,
        provider: str,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None,
    ) -> str:
        """生成缓存键。"""
        # 序列化 messages 为规范 JSON（确保顺序一致）
        msg_json = json.dumps(messages, sort_keys=True, ensure_ascii=False)
        raw = f"{provider}|{model}|{msg_json}|{temperature}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def get(
        self,
        provider: str,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None,
        ttl: int,
    ) -> dict[str, Any] | None:
        """查找缓存。ttl=0 时禁用。返回响应 dict 或 None。"""
        if ttl <= 0:
            return None
        key = self._make_key(provider, model, messages, temperature)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, data = entry
            if time.monotonic() - ts > ttl:
                # 过期，惰性删除
                del self._store[key]
                return None
            return data

    def set(
        self,
        provider: str,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None,
        response: dict[str, Any],
    ) -> None:
        """写入缓存。"""
        key = self._make_key(provider, model, messages, temperature)
        with self._lock:
            # 容量控制：超过上限时清理最旧条目
            if len(self._store) >= self._max_size:
                oldest = min(self._store, key=lambda k: self._store[k][0])
                del self._store[oldest]
            self._store[key] = (time.monotonic(), response)

    def clear(self) -> int:
        """清空缓存，返回清除的条目数。"""
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    def stats(self) -> dict[str, int]:
        """返回缓存统计。"""
        with self._lock:
            return {"size": len(self._store), "max_size": self._max_size}


_cache: ResponseCache | None = None


def get_cache() -> ResponseCache:
    global _cache
    if _cache is None:
        _cache = ResponseCache()
    return _cache
