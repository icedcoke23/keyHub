"""健康检查与系统状态路由（无需认证）。"""

from __future__ import annotations

from fastapi import APIRouter

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
