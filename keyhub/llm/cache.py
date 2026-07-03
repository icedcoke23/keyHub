"""LLM 响应缓存（内存 LRU + TTL）。"""
from __future__ import annotations
import hashlib
import time
from collections import OrderedDict

class ResponseCache:
    """单例响应缓存。最大 256 条，惰性过期清理。"""
    _instance = None
    MAX_SIZE = 256

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._store = OrderedDict()  # key -> (response, expire_at)
        return cls._instance

    def _make_key(self, provider, model, messages, temperature, max_tokens) -> str:
        # sha256 前 16 位
        # max_tokens 必须纳入 key：相同 prompt 但 max_tokens 不同时上游会
        # 返回不同长度的补全，混用会导致截断或浪费。
        raw = f"{provider}|{model}|{temperature}|{max_tokens}|{repr(messages)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, provider, model, messages, temperature, ttl, max_tokens=None):
        if ttl <= 0:
            return None
        key = self._make_key(provider, model, messages, temperature, max_tokens)
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

    def set(self, provider, model, messages, temperature, response, max_tokens=None):
        from ..config import get_settings
        ttl = get_settings().llm_cache_ttl
        if ttl <= 0:
            return
        key = self._make_key(provider, model, messages, temperature, max_tokens)
        self._store[key] = (response, time.time() + ttl)
        self._store.move_to_end(key)
        # 容量控制
        while len(self._store) > self.MAX_SIZE:
            self._store.popitem(last=False)

    def clear(self) -> int:
        n = len(self._store)
        self._store.clear()
        return n

    def stats(self) -> dict:
        return {"size": len(self._store), "max_size": self.MAX_SIZE}

def get_cache() -> ResponseCache:
    return ResponseCache()
