"""LLM 响应缓存（内存 LRU + TTL）。"""
from __future__ import annotations
import hashlib
import threading
import time
from collections import OrderedDict


class ResponseCache:
    """单例响应缓存。最大 256 条，惰性过期清理。

    线程安全：所有 _store 操作均在 _lock 内完成，避免并发
    move_to_end / popitem 竞态导致 OrderedDict 内部状态损坏。
    """
    _instance = None
    _inst_lock = threading.Lock()
    MAX_SIZE = 256

    def __new__(cls):
        with cls._inst_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._store: OrderedDict[str, tuple] = OrderedDict()
                inst._lock = threading.Lock()
                cls._instance = inst
            return cls._instance

    def _make_key(self, provider, model, messages, temperature,
                  max_tokens=None, extra=None) -> str:
        # sha256 前 16 位。max_tokens/extra 影响输出，必须纳入 key，
        # 否则不同 max_tokens/extra 的请求会命中同一缓存返回错误结果。
        raw = f"{provider}|{model}|{temperature}|{max_tokens}|{repr(extra)}|{repr(messages)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, provider, model, messages, temperature, ttl,
            max_tokens=None, extra=None):
        if ttl <= 0:
            return None
        key = self._make_key(provider, model, messages, temperature, max_tokens, extra)
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            resp, expire_at = item
            if time.time() > expire_at:
                del self._store[key]
                return None
            # LRU: 移到末尾
            self._store.move_to_end(key)
            return resp

    def set(self, provider, model, messages, temperature, response,
            max_tokens=None, extra=None):
        from ..config import get_settings
        ttl = get_settings().llm_cache_ttl
        if ttl <= 0:
            return
        key = self._make_key(provider, model, messages, temperature, max_tokens, extra)
        with self._lock:
            self._store[key] = (response, time.time() + ttl)
            self._store.move_to_end(key)
            # 容量控制
            while len(self._store) > self.MAX_SIZE:
                self._store.popitem(last=False)

    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    def stats(self) -> dict:
        with self._lock:
            return {"size": len(self._store), "max_size": self.MAX_SIZE}


def get_cache() -> ResponseCache:
    return ResponseCache()
