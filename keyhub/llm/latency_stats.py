"""LLM 调用延迟分位数统计。

维护每个 (provider, model) 组合的滑动窗口延迟数据，
支持 P50/P95/P99 查询。
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime

from sqlalchemy import desc, select, func

from ..db import session_scope
from ..models import LLMKey, UsageLog


class LatencyStats:
    """延迟分位数统计器（单例）。

    内存中维护每个 provider 的最近 N 次延迟，
    同时支持从数据库查询历史 P50/P95。
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._windows = {}  # provider -> deque
                cls._instance._window_size = 100
                cls._instance._data_lock = threading.Lock()
            return cls._instance

    def record(self, provider: str, latency_ms: int) -> None:
        """记录一次延迟。"""
        with self._data_lock:
            if provider not in self._windows:
                self._windows[provider] = deque(maxlen=self._window_size)
            self._windows[provider].append(latency_ms)

    def percentiles(self, provider: str) -> dict:
        """返回 P50/P95/P99 延迟（毫秒）。"""
        with self._data_lock:
            data = sorted(self._windows.get(provider, []))
        if not data:
            return {"p50": 0, "p95": 0, "p99": 0, "count": 0}
        n = len(data)
        return {
            "p50": data[int(n * 0.5)],
            "p95": data[int(n * 0.95)] if n >= 20 else data[-1],
            "p99": data[int(n * 0.99)] if n >= 100 else data[-1],
            "count": n,
        }

    def all_percentiles(self) -> dict:
        """返回所有 provider 的分位数。"""
        with self._data_lock:
            providers = list(self._windows.keys())
        return {p: self.percentiles(p) for p in providers}

    def db_percentiles(self, provider: str | None = None, limit: int = 1000) -> dict:
        """从数据库查询历史延迟分位数。"""
        with session_scope() as s:
            stmt = select(UsageLog.latency_ms, LLMKey.provider).join(
                LLMKey, UsageLog.llm_key_id == LLMKey.id
            ).where(UsageLog.success == True).order_by(desc(UsageLog.created_at)).limit(limit)  # noqa: E712
            if provider:
                stmt = stmt.where(LLMKey.provider == provider)
            rows = s.execute(stmt).all()

        result = {}
        for latency_ms, prov in rows:
            if prov not in result:
                result[prov] = []
            result[prov].append(latency_ms)

        return {
            prov: {
                "p50": sorted(data)[int(len(data) * 0.5)] if data else 0,
                "p95": sorted(data)[int(len(data) * 0.95)] if len(data) >= 20 else (sorted(data)[-1] if data else 0),
                "p99": sorted(data)[int(len(data) * 0.99)] if len(data) >= 100 else (sorted(data)[-1] if data else 0),
                "count": len(data),
            }
            for prov, data in result.items()
        }


_stats: LatencyStats | None = None

def get_latency_stats() -> LatencyStats:
    global _stats
    if _stats is None:
        _stats = LatencyStats()
    return _stats
