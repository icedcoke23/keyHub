"""Per-Key RPM/TPM 滑动窗口限流。

使用 60 秒滑动窗口，按 key_id 维度统计请求数和 token 数。
- RPM limit: 每分钟请求数上限
- TPM limit: 每分钟 token 数上限
- 0 表示不限流
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional, Tuple

from ..config import get_settings

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

    def _current_rpm(self, key_id: str) -> int:
        q = self._requests.get(key_id)
        return len(q) if q is not None else 0

    def _current_tpm(self, key_id: str) -> int:
        q = self._tokens.get(key_id)
        if q is None:
            return 0
        return sum(t for _, t in q)

    def check(self, key_id: str, tokens: int = 0) -> Tuple[bool, int, int]:
        """检查是否允许本次请求。

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
                cur_rpm = self._current_rpm(key_id)
                cur_tpm = self._current_tpm(key_id)

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

            return allowed, rpm_remaining, tpm_remaining
        except Exception:
            return True, -1, -1

    def record(self, key_id: str, tokens: int = 0) -> None:
        """记录一次已完成的请求。"""
        try:
            now = time.monotonic()
            with self._data_lock:
                if key_id not in self._requests:
                    self._requests[key_id] = deque()
                self._requests[key_id].append(now)

                if tokens > 0:
                    if key_id not in self._tokens:
                        self._tokens[key_id] = deque()
                    self._tokens[key_id].append((now, tokens))

                self._prune(key_id, now)

                if not self._requests[key_id] and not self._tokens.get(key_id):
                    self._requests.pop(key_id, None)
                    self._tokens.pop(key_id, None)
        except Exception:
            pass


def get_key_rate_limiter() -> KeyRateLimiter:
    return KeyRateLimiter()
