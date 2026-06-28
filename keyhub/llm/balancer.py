"""多 key 负载均衡器。

策略（可配置）：
1. round_robin（默认）：按优先级分组，组内轮询
2. latency：选最近平均延迟最低的 key
3. cost：选同 provider 中成本最低的 model（按 estimated_cost_usd 最低）
4. weighted：按 weight 字段加权随机

通用流程：
1. 选取指定 provider 下 status=active 且不在冷却期的 key
2. 按策略从候选中选择
3. 调用失败 → 标记冷却（rate_limited）→ 切换下一个 key
4. 全部不可用 → 抛 NoAvailableKeyError
"""

from __future__ import annotations

import random
import threading
import time
from datetime import datetime, timedelta
from typing import Iterator

from sqlalchemy import select, update

from ..config import get_settings
from ..db import session_scope
from ..models import LLMKey, LLMKeyStatus

# 冷却时长（秒）
RATE_LIMIT_COOLDOWN = 60
ERROR_COOLDOWN = 30


class NoAvailableKeyError(RuntimeError):
    pass


class KeyBalancer:
    _instance: "KeyBalancer | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "KeyBalancer":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._cursors = {}  # type: ignore[attr-defined]
            return cls._instance

    def _cursor(self, provider: str) -> int:
        return self._cursors.get(provider, 0)

    def _advance(self, provider: str, n: int) -> None:
        self._cursors[provider] = (self._cursors.get(provider, 0) + 1) % max(n, 1)

    def list_active(self, provider: str, model: str | None = None) -> list[LLMKey]:
        now = datetime.utcnow()
        with session_scope() as s:
            stmt = (
                select(LLMKey)
                .where(LLMKey.provider == provider)
                .where(LLMKey.status == LLMKeyStatus.active)
                .where((LLMKey.cooldown_until.is_(None)) | (LLMKey.cooldown_until < now))
            )
            rows = list(s.execute(stmt).scalars().all())
            # 脱离 session
            for r in rows:
                s.expunge(r)
        if model:
            rows = [r for r in rows if not r.allowed_models or model in r.allowed_models]
        return rows

    def pick(self, provider: str, model: str | None = None) -> LLMKey:
        """选一个 key 用于本次调用。返回的 LLMKey 已脱离 session。"""
        actives = self.list_active(provider, model)
        if not actives:
            raise NoAvailableKeyError(
                f"no active key for provider='{provider}'"
                + (f" model='{model}'" if model else "")
            )

        strategy = get_settings().llm_balance_strategy

        if strategy == "latency":
            # 选平均延迟最低的 key（延迟 0 视为无数据，排最后）
            return min(actives, key=lambda k: (k.avg_latency_ms if k.avg_latency_ms > 0 else 999999, k.id))

        if strategy == "cost":
            # 选累计成本最低的 key
            return min(actives, key=lambda k: (k.estimated_cost_usd, k.id))

        if strategy == "weighted":
            # 按权重加权随机
            weights = [max(k.weight, 1) for k in actives]
            return random.choices(actives, weights=weights, k=1)[0]

        # 默认 round_robin：按优先级分组，组内轮询
        max_pri = max(r.priority for r in actives)
        top = [r for r in actives if r.priority == max_pri]
        idx = self._cursor(provider) % len(top)
        chosen = top[idx]
        self._advance(provider, len(top))
        return chosen

    def mark_rate_limited(self, key_id: str) -> None:
        with session_scope() as s:
            s.execute(
                update(LLMKey)
                .where(LLMKey.id == key_id)
                .values(
                    status=LLMKeyStatus.rate_limited,
                    cooldown_until=datetime.utcnow() + timedelta(seconds=RATE_LIMIT_COOLDOWN),
                )
            )

    def mark_error(self, key_id: str) -> None:
        with session_scope() as s:
            s.execute(
                update(LLMKey)
                .where(LLMKey.id == key_id)
                .values(
                    status=LLMKeyStatus.error,
                    cooldown_until=datetime.utcnow() + timedelta(seconds=ERROR_COOLDOWN),
                )
            )

    def mark_ok(self, key_id: str, latency_ms: int = 0) -> None:
        """标记 key 恢复正常，并更新平均延迟（指数移动平均）。"""
        with session_scope() as s:
            k = s.get(LLMKey, key_id)
            if k is None:
                return
            k.status = LLMKeyStatus.active
            k.cooldown_until = None
            if latency_ms > 0:
                # 指数移动平均：新均值 = 0.7 * 旧均值 + 0.3 * 本次延迟
                if k.avg_latency_ms == 0:
                    k.avg_latency_ms = latency_ms
                else:
                    k.avg_latency_ms = int(0.7 * k.avg_latency_ms + 0.3 * latency_ms)


def get_balancer() -> KeyBalancer:
    return KeyBalancer()
