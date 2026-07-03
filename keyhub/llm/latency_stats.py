"""LLM 延迟分位数统计（P50/P95/P99）。

内存滑动窗口 + 数据库查询双路径：
- 内存窗口：最近 1000 次调用，快速返回分位数
- 数据库查询：从 usage_logs 表查询历史延迟
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta


class LatencyStats:
    """单例延迟统计器。"""
    _instance = None
    _lock = threading.Lock()
    WINDOW_SIZE = 1000

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._windows = {}  # provider -> deque
            return cls._instance

    def record(self, provider: str, latency_ms: int) -> None:
        """记录一次延迟样本。"""
        with self._lock:
            if provider not in self._windows:
                self._windows[provider] = deque(maxlen=self.WINDOW_SIZE)
            self._windows[provider].append(latency_ms)

    def percentiles(self, provider: str) -> tuple[float, float, float]:
        """返回 (P50, P95, P99)。内存窗口不足时回退到数据库查询。"""
        with self._lock:
            samples = list(self._windows.get(provider, []))
        if len(samples) >= 10:
            return self._compute_pct(samples)
        # 回退到数据库
        return self._query_db(provider)

    def _compute_pct(self, samples: list[int]) -> tuple[float, float, float]:
        s = sorted(samples)
        n = len(s)
        if n == 0:
            return 0.0, 0.0, 0.0
        if n == 1:
            return float(s[0]), float(s[0]), float(s[0])
        # 钳制索引上界为 n-1，避免 int(n*p) >= n 时 IndexError
        # p50 用标准中位数公式（偶数样本取中间两值平均）
        mid_lo = (n - 1) // 2
        mid_hi = n // 2
        p50 = (s[mid_lo] + s[mid_hi]) / 2
        p95 = s[min(int(n * 0.95), n - 1)]
        p99 = s[min(int(n * 0.99), n - 1)]
        return float(p50), float(p95), float(p99)

    def _query_db(self, provider: str) -> tuple[float, float, float]:
        """从 usage_logs 查询最近 24h 延迟分位数。"""
        try:
            from ..db import session_scope
            from ..models import UsageLog, LLMKey
            from sqlalchemy import select
            cutoff = datetime.utcnow() - timedelta(hours=24)
            with session_scope() as s:
                rows = s.execute(
                    select(UsageLog.latency_ms)
                    .join(LLMKey, UsageLog.llm_key_id == LLMKey.id)
                    .where(LLMKey.provider == provider)
                    .where(UsageLog.created_at >= cutoff)
                    .where(UsageLog.success == True)  # noqa: E712
                    .order_by(UsageLog.latency_ms)
                ).scalars().all()
            if not rows:
                return 0.0, 0.0, 0.0
            return self._compute_pct(list(rows))
        except Exception:
            return 0.0, 0.0, 0.0

    def all_providers(self) -> dict[str, dict]:
        """返回所有已记录 provider 的分位数。"""
        with self._lock:
            providers = list(self._windows.keys())
        result = {}
        for p in providers:
            p50, p95, p99 = self.percentiles(p)
            result[p] = {"p50": p50, "p95": p95, "p99": p99}
        return result


def get_latency_stats() -> LatencyStats:
    return LatencyStats()
