"""空闲自动锁定。

后台 daemon 线程定期检查最后活动时间，超时则调用 runtime.lock()。
"""
from __future__ import annotations

import threading
import time

from .config import get_settings
from .runtime import get_runtime


class AutoLockChecker:
    """单例自动锁定检查器。"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._last_activity = time.monotonic()
                cls._instance._thread = None
                cls._instance._running = False
            return cls._instance

    def touch(self):
        """更新最后活动时间（认证成功时调用）。"""
        self._last_activity = time.monotonic()

    def start(self):
        """启动后台检查线程。"""
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="auto-lock")
        self._thread.start()

    def stop(self):
        """停止后台检查线程。"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while self._running:
            idle = get_settings().auto_lock_idle_seconds
            if idle > 0:
                elapsed = time.monotonic() - self._last_activity
                if elapsed > idle:
                    rt = get_runtime()
                    if rt.unlocked:
                        rt.lock()
                        # 审计
                        try:
                            from .audit import record as audit_record
                            from .models import AuditAction
                            audit_record(AuditAction.auth_auto_lock, "system",
                                         detail={"idle_seconds": int(elapsed)})
                        except Exception:
                            pass
            time.sleep(10)  # 每 10 秒检查一次


def get_auto_lock_checker() -> AutoLockChecker:
    return AutoLockChecker()
