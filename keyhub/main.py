"""FastAPI 主应用。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api import auth as auth_api
from .api import audit as audit_api
from .api import credentials as cred_api
from .api import llm as llm_api
from .api import rotation as rot_api
from .api import system as sys_api
from .config import get_settings
from .db import init_db
from .rotation import get_checker


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 配置结构化日志
    from .structured_logging import setup_logging
    setup_logging("INFO")
    # 启动
    init_db()
    from .notify import get_notifier

    def _on_remind(reminders):
        notifier = get_notifier()
        payload = {
            "count": len(reminders),
            "items": [
                {
                    "name": r.name,
                    "type": r.type.value,
                    "days_until_expire": r.days_until_expire,
                    "days_since_rotation": r.days_since_rotation,
                }
                for r in reminders
            ],
        }
        notifier.notify("rotation.reminder", payload)

    checker = get_checker()
    checker.start(on_remind=_on_remind)

    # 启动空闲自动锁定
    from .auto_lock import get_auto_lock_checker
    auto_lock = get_auto_lock_checker()
    auto_lock.start()

    # 清理过期审计日志
    settings = get_settings()
    if settings.audit_retention_days > 0:
        from .audit import cleanup_old_logs
        deleted = cleanup_old_logs(settings.audit_retention_days)
        if deleted:
            print(f"[audit] cleaned up {deleted} old log entries", flush=True)

    yield
    # 关闭
    checker.stop()
    auto_lock.stop()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="KeyHub",
        version="0.1.0",
        description="个人密钥与大模型 API 凭证管理",
        lifespan=lifespan,
    )

    # 路由
    app.include_router(sys_api.router)
    app.include_router(auth_api.router)
    app.include_router(cred_api.router)
    app.include_router(llm_api.router)
    app.include_router(rot_api.router)
    app.include_router(audit_api.router)
    # 实时事件 SSE
    from .api import events as events_api
    app.include_router(events_api.router)
    # OpenAI 兼容 API
    from .api import v1 as v1_api
    app.include_router(v1_api.router)
    # Prometheus 指标
    from .metrics import router as metrics_router
    app.include_router(metrics_router)

    # Web UI
    if settings.web_ui:
        from .web import mount_web_ui
        mount_web_ui(app)

    return app


app = create_app()
