"""审计日志查询路由。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..audit import list_logs
from ..auth import require_auth
from ..models import AuditAction

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/logs")
def logs(
    limit: int = Query(100, le=1000),
    action: AuditAction | None = Query(None),
    target: str | None = Query(None),
    success: bool | None = Query(None),
    _: str = Depends(require_auth),
):
    """查询审计日志。可按 action / target / success 过滤。"""
    return list_logs(limit=limit, action=action, target=target, success_only=success)
