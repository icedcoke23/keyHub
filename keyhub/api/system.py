"""健康检查与系统状态路由（无需认证）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import require_scope
from ..notify import get_notifier
from ..runtime import get_runtime

router = APIRouter(tags=["system"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/api/status")
def status():
    rt = get_runtime()
    s = rt.status()
    return {
        "initialized": s.initialized,
        "locked": s.locked,
        "unlocked": rt.unlocked,
    }


@router.post("/api/notify/test")
def test_notify(_: str = Depends(require_scope("admin:write"))):
    """发送一条测试通知，用于验证 Webhook / 邮件配置。"""
    get_notifier().notify("test.notification", {"message": "test from KeyHub API"})
    return {"message": "notification sent"}
