"""空闲自动锁定：超过配置时长无活动则自动锁定 vault。"""
import threading
import time
from datetime import datetime
from .config import get_settings
from .runtime import get_runtime
from .audit import record as audit_record
from .models import AuditAction

class AutoLockChecker:
    """单例。后台 daemon 线程定期检查空闲时间。"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._last_activity = time.monotonic()
                cls._instance._thread = None
                cls._instance._running = False
                cls._instance._activity_lock = threading.Lock()
            return cls._instance

    def touch(self):
        """更新最后活动时间。每次 API 请求时应调用。"""
        with self._activity_lock:
            self._last_activity = time.monotonic()

    def start(self):
        settings = get_settings()
        if settings.auto_lock_idle_seconds <= 0:
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="auto-lock")
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        settings = get_settings()
        interval = min(settings.auto_lock_idle_seconds, 60)  # 检查间隔不超过 60s
        while self._running:
            time.sleep(interval)
            if not self._running:
                break
            rt = get_runtime()
            if not rt.unlocked:
                continue
            with self._activity_lock:
                idle = time.monotonic() - self._last_activity
            if idle >= settings.auto_lock_idle_seconds:
                rt.lock()
                audit_record(AuditAction.auth_auto_lock, "system",
                             detail={"idle_seconds": int(idle)})

def get_auto_lock_checker() -> AutoLockChecker:
    return AutoLockChecker()
