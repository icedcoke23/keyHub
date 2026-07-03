"""多 key 负载均衡器。

策略：
1. 选取指定 provider 下 status=active 且不在冷却期的 key
2. 按 priority 降序取最高优先级组
3. 组内轮询（round-robin，基于内存游标）
4. 调用失败 → 标记冷却（rate_limited/error）→ 切换下一个 key
5. 连续失败达阈值 → 熔断器打开，冷却300秒
6. 冷却期过半进入半开状态，允许一次试探请求
7. 全部不可用 → 抛 NoAvailableKeyError
"""

from __future__ import annotations

import email.utils
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import or_, select, update

from ..db import session_scope
from ..models import LLMKey, LLMKeyStatus

RATE_LIMIT_COOLDOWN = 60
ERROR_COOLDOWN = 30

CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_COOLDOWN = 300


class NoAvailableKeyError(RuntimeError):
    pass


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """解析 Retry-After 头，返回秒数；解析失败返回 None。

    支持两种格式：
    - 秒数（delta-seconds）
    - HTTP-date（IMF-fixdate，如 "Wed, 21 Oct 2015 07:28:00 GMT"）
    """
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except (ValueError, TypeError):
        pass
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (dt - now).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


class KeyBalancer:
    _instance: Optional["KeyBalancer"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "KeyBalancer":
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._cursors: dict[str, int] = {}
                inst._fail_counts: dict[str, int] = {}
                inst._cb_open_until: dict[str, float] = {}
                inst._half_open: dict[str, float] = {}
                inst._inflight: dict[str, int] = {}
                inst._state_lock = threading.Lock()
                inst._last_self_heal = 0.0  # type: ignore[attr-defined]
                inst._self_heal_interval = 30.0  # type: ignore[attr-defined]
                cls._instance = inst
            return cls._instance

    def _cursor(self, provider: str) -> int:
        return self._cursors.get(provider, 0)

    def _advance(self, provider: str, n: int) -> None:
        self._cursors[provider] = (self._cursors.get(provider, 0) + 1) % max(n, 1)

    def _cb_state(self, key_id: str, now_ts: float) -> str:
        """返回 key 的熔断器状态: 'closed' / 'open' / 'half_open' / 'probing'。"""
        open_until = self._cb_open_until.get(key_id)
        if open_until is None:
            return "closed"
        if now_ts >= open_until:
            return "closed"
        half_open_at = open_until - CIRCUIT_BREAKER_COOLDOWN / 2
        if now_ts < half_open_at:
            return "open"
        if key_id in self._half_open:
            return "probing"
        return "half_open"

    def _on_failure(self, key_id: str) -> bool:
        """记录一次连续失败。返回 True 表示触发熔断。"""
        with self._state_lock:
            count = self._fail_counts.get(key_id, 0) + 1
            self._fail_counts[key_id] = count
            if count >= CIRCUIT_BREAKER_THRESHOLD:
                self._cb_open_until[key_id] = time.monotonic() + CIRCUIT_BREAKER_COOLDOWN
                self._half_open.pop(key_id, None)
                return True
            return False

    def _on_success(self, key_id: str) -> None:
        """成功时重置熔断器状态。"""
        with self._state_lock:
            self._fail_counts.pop(key_id, None)
            self._cb_open_until.pop(key_id, None)
            self._half_open.pop(key_id, None)

    def _claim_half_open(self, key_id: str) -> bool:
        """尝试认领半开试探权，返回是否成功。"""
        with self._state_lock:
            if key_id in self._half_open:
                return False
            self._half_open[key_id] = time.monotonic()
            return True

    def acquire(self, key_id: str) -> None:
        """增加 key 的在飞请求计数。"""
        with self._state_lock:
            self._inflight[key_id] = self._inflight.get(key_id, 0) + 1

    def release(self, key_id: str) -> None:
        """减少 key 的在飞请求计数。"""
        with self._state_lock:
            current = self._inflight.get(key_id, 0)
            if current > 0:
                self._inflight[key_id] = current - 1
            else:
                self._inflight[key_id] = 0

    def _cleanup(self, now_ts: float) -> None:
        """清理过期的熔断器内存状态，并自愈 DB 中过期的 circuit_breaker key。

        修复 H8：原先冷却到期后仅清理内存追踪，DB 中 status 仍为
        circuit_breaker，导致 key 永久不可选。现在主动将 cooldown 已
        过期的 circuit_breaker key 重置为 active，覆盖：
        - 内存追踪的过期 key
        - 进程重启后遗留的过期 CB key（内存丢失但 DB 仍在）
        """
        with self._state_lock:
            expired = [
                k for k, v in self._cb_open_until.items()
                if now_ts >= v
            ]
            for k in expired:
                self._fail_counts.pop(k, None)
                self._cb_open_until.pop(k, None)
                self._half_open.pop(k, None)

        # DB 自愈（节流：每 _self_heal_interval 秒最多一次，UPDATE 幂等）
        with self._state_lock:
            due = now_ts - self._last_self_heal >= self._self_heal_interval
            if due:
                self._last_self_heal = now_ts
        if due:
            self._self_heal_db()

    def _self_heal_db(self) -> None:
        """将 cooldown_until 已过期的 circuit_breaker key 重置为 active。"""
        try:
            now = datetime.utcnow()
            with session_scope() as s:
                s.execute(
                    update(LLMKey)
                    .where(
                        LLMKey.status == LLMKeyStatus.circuit_breaker,
                        LLMKey.cooldown_until.is_not(None),
                        LLMKey.cooldown_until < now,
                    )
                    .values(status=LLMKeyStatus.active, cooldown_until=None)
                )
        except Exception:
            pass

    def _query_active_keys(self, provider: Optional[str], model: Optional[str] = None) -> list[LLMKey]:
        now = datetime.utcnow()
        now_ts = time.monotonic()
        self._cleanup(now_ts)

        fully_broken: set[str] = set()
        half_open_available: set[str] = set()
        with self._state_lock:
            for key_id in self._cb_open_until:
                state = self._cb_state(key_id, now_ts)
                if state == "open" or state == "probing":
                    fully_broken.add(key_id)
                elif state == "half_open":
                    half_open_available.add(key_id)

        with session_scope() as s:
            cond_active = (LLMKey.status == LLMKeyStatus.active) & (
                (LLMKey.cooldown_until.is_(None)) | (LLMKey.cooldown_until < now)
            )
            base_conditions: list = []
            if provider is not None:
                base_conditions.append(LLMKey.provider == provider)
            if half_open_available:
                cond_cb_half = (LLMKey.status == LLMKeyStatus.circuit_breaker) & (
                    LLMKey.id.in_(half_open_available)
                )
                if provider is not None:
                    stmt = select(LLMKey).where(
                        LLMKey.provider == provider,
                        or_(cond_active, cond_cb_half),
                    )
                else:
                    stmt = select(LLMKey).where(or_(cond_active, cond_cb_half))
            else:
                conditions = list(base_conditions) + [cond_active]
                stmt = select(LLMKey).where(*conditions)
            rows = list(s.execute(stmt).scalars().all())
            for r in rows:
                s.expunge(r)

        rows = [r for r in rows if r.id not in fully_broken]
        if model:
            rows = [r for r in rows if not r.allowed_models or model in r.allowed_models]
        return rows

    def list_active(self, provider: str, model: Optional[str] = None) -> list[LLMKey]:
        return self._query_active_keys(provider, model)

    def _select_key(self, candidates: list[LLMKey], provider: str) -> LLMKey:
        max_pri = max(r.priority for r in candidates)
        top = [r for r in candidates if r.priority == max_pri]

        half_open_keys = [k for k in top if k.status == LLMKeyStatus.circuit_breaker]
        if half_open_keys:
            chosen = half_open_keys[0]
            self._claim_half_open(chosen.id)
        else:
            from ..config import get_settings
            strategy = get_settings().llm_balance_strategy
            if strategy == "latency":
                chosen = min(top, key=lambda k: (k.avg_latency_ms or 999999, k.id))
            elif strategy == "cost":
                chosen = min(top, key=lambda k: (k.estimated_cost_usd, k.id))
            elif strategy == "weighted":
                chosen = random.choices(top, weights=[max(k.weight, 1) for k in top], k=1)[0]
            elif strategy == "least_used":
                with self._state_lock:
                    chosen = min(top, key=lambda k: (self._inflight.get(k.id, 0), k.id))
            else:
                idx = self._cursor(provider) % len(top)
                chosen = top[idx]
                self._advance(provider, len(top))
        return chosen

    def pick(self, provider: str, model: Optional[str] = None) -> LLMKey:
        """选一个 key 用于本次调用。返回的 LLMKey 已脱离 session。"""
        actives = self.list_active(provider, model)
        if not actives:
            raise NoAvailableKeyError(
                f"no active key for provider='{provider}'"
                + (f" model='{model}'" if model else "")
            )

        chosen = self._select_key(actives, provider)
        self.acquire(chosen.id)
        return chosen

    def pick_cross_provider(self, model: str, exclude_provider: Optional[str] = None) -> tuple[str, LLMKey]:
        """跨 provider 选择一个可用 key。返回 (provider, key)。"""
        all_actives = self._query_active_keys(None, model)
        if exclude_provider:
            all_actives = [k for k in all_actives if k.provider != exclude_provider]
        if not all_actives:
            raise NoAvailableKeyError(
                f"no active key across all providers for model='{model}'"
            )

        providers = sorted({k.provider for k in all_actives})
        for prov in providers:
            candidates = [k for k in all_actives if k.provider == prov]
            if candidates:
                chosen = self._select_key(candidates, prov)
                self.acquire(chosen.id)
                return prov, chosen
        raise NoAvailableKeyError(
            f"no active key across all providers for model='{model}'"
        )

    def mark_rate_limited(self, key_id: str, retry_after: Optional[float] = None) -> None:
        try:
            triggered_cb = self._on_failure(key_id)
            if triggered_cb:
                cooldown_dt = datetime.utcnow() + timedelta(seconds=CIRCUIT_BREAKER_COOLDOWN)
                status = LLMKeyStatus.circuit_breaker
            else:
                cooldown_sec = retry_after if (retry_after is not None and retry_after > 0) else RATE_LIMIT_COOLDOWN
                cooldown_dt = datetime.utcnow() + timedelta(seconds=cooldown_sec)
                status = LLMKeyStatus.rate_limited
            with session_scope() as s:
                s.execute(
                    update(LLMKey)
                    .where(LLMKey.id == key_id)
                    .values(status=status, cooldown_until=cooldown_dt)
                )
        except Exception:
            pass
        finally:
            self.release(key_id)

    def mark_error(self, key_id: str) -> None:
        try:
            triggered_cb = self._on_failure(key_id)
            if triggered_cb:
                cooldown_dt = datetime.utcnow() + timedelta(seconds=CIRCUIT_BREAKER_COOLDOWN)
                status = LLMKeyStatus.circuit_breaker
            else:
                cooldown_dt = datetime.utcnow() + timedelta(seconds=ERROR_COOLDOWN)
                status = LLMKeyStatus.error
            with session_scope() as s:
                s.execute(
                    update(LLMKey)
                    .where(LLMKey.id == key_id)
                    .values(status=status, cooldown_until=cooldown_dt)
                )
        except Exception:
            pass
        finally:
            self.release(key_id)

    def mark_ok(self, key_id: str, latency_ms: Optional[int] = None) -> None:
        try:
            self._on_success(key_id)
            with session_scope() as s:
                values: dict = {"status": LLMKeyStatus.active, "cooldown_until": None}
                if latency_ms is not None:
                    key = s.get(LLMKey, key_id)
                    if key is not None:
                        old = key.avg_latency_ms or 0
                        if old == 0:
                            new_latency = int(latency_ms)
                        else:
                            new_latency = int(0.7 * old + 0.3 * latency_ms)
                        values["avg_latency_ms"] = new_latency
                s.execute(
                    update(LLMKey)
                    .where(LLMKey.id == key_id)
                    .values(**values)
                )
        except Exception:
            pass
        finally:
            self.release(key_id)


def get_balancer() -> KeyBalancer:
    return KeyBalancer()
