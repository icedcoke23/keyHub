"""Per-Key RPM/TPM 滑动窗口限流。

使用 60 秒滑动窗口，按 key_id 维度统计请求数和 token 数。
- RPM limit: 每分钟请求数上限
- TPM limit: 每分钟 token 数上限
- 0 表示不限流

并发安全说明：
- RPM 采用「检查即占用」原子模式：check() 通过即在持锁状态下 append
  请求时间戳，避免 N 个并发请求都通过 check 后才 record 导致超限。
- TPM 因请求前不知道 token 数，check() 仅做乐观预估（传入预估值），
  请求完成后由 record() 回填真实 token 数；若累计超限，下次 check 会拒绝。
- 所有异常走 logger.exception 后保守放行（fail-open 仅限限流本身，
  不阻塞业务），但会留下日志便于排查。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Optional, Tuple

from ..config import get_settings

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60


class KeyRateLimiter:
    _instance: Optional["KeyRateLimiter"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "KeyRateLimiter":
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._requests: dict[str, deque[float]] = {}
                inst._tokens: dict[str, deque[Tuple[float, int]]] = {}
                inst._data_lock = threading.Lock()
                cls._instance = inst
            return cls._instance

    def _prune(self, key_id: str, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        req_q = self._requests.get(key_id)
        if req_q is not None:
            while req_q and req_q[0] < cutoff:
                req_q.popleft()
        tok_q = self._tokens.get(key_id)
        if tok_q is not None:
            while tok_q and tok_q[0][0] < cutoff:
                tok_q.popleft()

    def _cleanup_if_empty(self, key_id: str) -> None:
        """窗口内无样本时清理 key 条目，防止已删除 key 永久驻留内存。"""
        req_q = self._requests.get(key_id)
        tok_q = self._tokens.get(key_id)
        if (req_q is None or len(req_q) == 0) and (tok_q is None or len(tok_q) == 0):
            self._requests.pop(key_id, None)
            self._tokens.pop(key_id, None)

    def check(self, key_id: str, tokens: int = 0) -> Tuple[bool, int, int]:
        """检查是否允许本次请求，通过则原子占用一个 RPM 槽位。

        Args:
            key_id: LLM key id
            tokens: 预估 token 数（用于 TPM 乐观预估，请求完成后由 record 回填真实值）

        Returns:
            (allowed, rpm_remaining, tpm_remaining)
            - allowed: 是否允许
            - rpm_remaining: 剩余请求额度（-1 表示不限）
            - tpm_remaining: 剩余 token 额度（-1 表示不限）
        """
        try:
            settings = get_settings()
            rpm_limit = settings.llm_key_rpm_limit
            tpm_limit = settings.llm_key_tpm_limit

            if (not rpm_limit or rpm_limit <= 0) and (not tpm_limit or tpm_limit <= 0):
                return True, -1, -1

            now = time.monotonic()
            with self._data_lock:
                self._prune(key_id, now)
                req_q = self._requests.get(key_id)
                cur_rpm = len(req_q) if req_q is not None else 0
                tok_q = self._tokens.get(key_id)
                cur_tpm = sum(t for _, t in tok_q) if tok_q else 0

                rpm_remaining = -1
                tpm_remaining = -1
                allowed = True

                if rpm_limit and rpm_limit > 0:
                    rpm_remaining = max(0, rpm_limit - cur_rpm)
                    if cur_rpm >= rpm_limit:
                        allowed = False
                if tpm_limit and tpm_limit > 0:
                    projected = cur_tpm + tokens
                    tpm_remaining = max(0, tpm_limit - cur_tpm)
                    if projected > tpm_limit:
                        allowed = False

                # 原子占用：通过 check 立即 append 请求时间戳，
                # 避免并发请求在锁外通过 check 后各自 record 导致 RPM 超限。
                if allowed:
                    if req_q is None:
                        req_q = deque()
                        self._requests[key_id] = req_q
                    req_q.append(now)

            return allowed, rpm_remaining, tpm_remaining
        except Exception:
            # 限流本身异常不应阻塞业务，但需留日志便于排查
            logger.exception("key rate limiter check failed for key=%s", key_id)
            return True, -1, -1

    def record(self, key_id: str, tokens: int = 0) -> None:
        """记录一次已完成请求的 token 数（TPM 回填）。

        RPM 槽位已在 check() 时原子占用，此处仅回填 TPM。
        """
        if tokens <= 0:
            return
        try:
            now = time.monotonic()
            with self._data_lock:
                self._prune(key_id, now)
                tok_q = self._tokens.get(key_id)
                if tok_q is None:
                    tok_q = deque()
                    self._tokens[key_id] = tok_q
                tok_q.append((now, tokens))
                self._cleanup_if_empty(key_id)
        except Exception:
            logger.exception("key rate limiter record failed for key=%s", key_id)

    def release_rpm_slot(self, key_id: str) -> None:
        """请求被拒或失败时回退 check() 占用的 RPM 槽位。

        调用时机：check() 通过但后续 balancer 选 key 失败 / 上游立即失败，
        让该次未真正发起的请求不占用 RPM 额度。
        """
        try:
            with self._data_lock:
                req_q = self._requests.get(key_id)
                if req_q and len(req_q) > 0:
                    req_q.pop()  # 移除最近 append 的一条
                self._cleanup_if_empty(key_id)
        except Exception:
            logger.exception("key rate limiter release failed for key=%s", key_id)


def get_key_rate_limiter() -> KeyRateLimiter:
    return KeyRateLimiter()
