"""轮换提醒：检查到期/超期未轮换的凭证。

提醒方式：
- 将提醒写入内存列表（API 可读）
- 打印到日志（个人自用，足够）
- 未来可扩展邮件 / webhook
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .models import Credential
from .schemas import RotationReminder


class RotationChecker:
    _instance: "RotationChecker | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "RotationChecker":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._reminders = []  # type: ignore[attr-defined]
                cls._instance._last_check = None  # type: ignore[attr-defined]
                cls._instance._stop = threading.Event()  # type: ignore[attr-defined]
                cls._instance._thread = None  # type: ignore[attr-defined]
            return cls._instance

    def check_once(self) -> list[RotationReminder]:
        now = datetime.utcnow()
        warn_days = get_settings().rotation_warn_days
        reminders: list[RotationReminder] = []

        with session_scope() as s:
            rows = s.execute(
                select(Credential).where(Credential.deleted == False)  # noqa: E712
            ).scalars().all()
            for c in rows:
                days_until_expire = None
                if c.expires_at:
                    days_until_expire = (c.expires_at - now).days
                days_since_rotation = None
                if c.last_rotated_at:
                    days_since_rotation = (now - c.last_rotated_at).days

                need_remind = False
                # 1) 即将到期
                if days_until_expire is not None and 0 <= days_until_expire <= warn_days:
                    need_remind = True
                # 2) 已过期
                if days_until_expire is not None and days_until_expire < 0:
                    need_remind = True
                # 3) 超过建议轮换周期
                if (
                    c.rotation_days
                    and c.last_rotated_at
                    and days_since_rotation is not None
                    and days_since_rotation >= c.rotation_days
                ):
                    need_remind = True
                # 4) 设置了 rotation_days 但从未轮换
                if c.rotation_days and not c.last_rotated_at:
                    need_remind = True

                if need_remind:
                    reminders.append(RotationReminder(
                        credential_id=c.id,
                        name=c.name,
                        type=c.type,
                        expires_at=c.expires_at,
                        last_rotated_at=c.last_rotated_at,
                        days_until_expire=days_until_expire,
                        days_since_rotation=days_since_rotation,
                    ))

        self._reminders = reminders
        self._last_check = now
        return reminders

    def get_reminders(self) -> list[RotationReminder]:
        if self._last_check is None:
            return self.check_once()
        return list(self._reminders)

    # ===== 后台线程 =====

    def start(self, on_remind: Callable[[list[RotationReminder]], None] | None = None) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        interval = get_settings().rotation_check_interval

        def _loop():
            while not self._stop.is_set():
                try:
                    rs = self.check_once()
                    if rs and on_remind:
                        on_remind(rs)
                except Exception as e:  # noqa: BLE001
                    # 后台任务异常不应崩溃
                    print(f"[rotation] check failed: {e}", flush=True)
                self._stop.wait(interval)

        self._thread = threading.Thread(target=_loop, daemon=True, name="rotation-checker")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


def get_checker() -> RotationChecker:
    return RotationChecker()
