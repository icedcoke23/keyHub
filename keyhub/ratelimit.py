"""基于内存的登录限流与失败锁定。

策略：
- 按 client_ip 维度计数失败次数
- 达到阈值后锁定该 IP 一段时间（指数退避）
- 成功登录后重置该 IP 计数
- 进程内 dict + threading.Lock，单进程方案（适合个人自用 + uvicorn 单 worker）

不依赖外部存储（Redis 等），重启后状态丢失（可接受：Argon2id 本身拖慢暴力破解）。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _AttemptState:
    fails: int = 0
    locked_until: float = 0.0  # monotonic 时间戳


class LoginRateLimiter:
    """登录失败限流器。

    参数：
    - max_fails：锁定前允许的失败次数
    - base_lock_seconds：首次锁定时长；后续按指数退避（base * 2^(fails - max_fails)）
    - max_lock_seconds：锁定时长上限
    """

    def __init__(
        self,
        max_fails: int = 5,
        base_lock_seconds: int = 60,
        max_lock_seconds: int = 3600,
    ) -> None:
        self.max_fails = max_fails
        self.base_lock = base_lock_seconds
        self.max_lock = max_lock_seconds
        self._state: dict[str, _AttemptState] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def is_locked(self, ip: str) -> tuple[bool, int]:
        """返回 (是否锁定, 剩余秒数)。"""
        with self._lock:
            st = self._state.get(ip)
            if st is None:
                return False, 0
            if st.locked_until <= self._now():
                return False, 0
            remaining = int(st.locked_until - self._now())
            return True, max(remaining, 0)

    def record_failure(self, ip: str) -> tuple[bool, int]:
        """记录一次失败。返回 (是否触发锁定, 锁定秒数)。"""
        with self._lock:
            st = self._state.setdefault(ip, _AttemptState())
            st.fails += 1
            if st.fails >= self.max_fails:
                # 指数退避：每次触发锁定时长翻倍，上限 max_lock
                excess = st.fails - self.max_fails
                lock_secs = min(self.base_lock * (2 ** excess), self.max_lock)
                st.locked_until = self._now() + lock_secs
                return True, int(lock_secs)
            return False, 0

    def record_success(self, ip: str) -> None:
        """成功登录后重置该 IP 计数。"""
        with self._lock:
            self._state.pop(ip, None)

    def reset(self, ip: str | None = None) -> None:
        """重置指定 IP 或全部状态（测试用）。"""
        with self._lock:
            if ip is None:
                self._state.clear()
            else:
                self._state.pop(ip, None)


# 单例
_limiter: LoginRateLimiter | None = None


def get_limiter() -> LoginRateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = LoginRateLimiter()
    return _limiter


class TokenRateLimiter:
    """按 API Token ID 的每分钟请求数限制。

    滑动窗口实现，内存 dict + threading.Lock。
    """
    def __init__(self, rpm: int = 60):
        self.rpm = rpm
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, token_id: str) -> tuple[bool, int]:
        """检查是否允许请求。返回 (允许, 剩余配额)。"""
        if self.rpm <= 0:
            return True, -1
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            timestamps = self._windows.get(token_id, [])
            # 清理过期时间戳
            timestamps = [t for t in timestamps if t > window_start]
            if len(timestamps) >= self.rpm:
                self._windows[token_id] = timestamps
                return False, 0
            timestamps.append(now)
            self._windows[token_id] = timestamps
            return True, self.rpm - len(timestamps)

    def reset(self, token_id: str | None = None):
        with self._lock:
            if token_id is None:
                self._windows.clear()
            else:
                self._windows.pop(token_id, None)

_token_limiter: TokenRateLimiter | None = None

def get_token_limiter() -> TokenRateLimiter:
    global _token_limiter
    if _token_limiter is None:
        from .config import get_settings
        _token_limiter = TokenRateLimiter(rpm=get_settings().token_rpm_limit)
    return _token_limiter
