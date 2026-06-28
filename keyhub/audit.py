"""审计日志模块。

提供 record() 记录敏感操作、list_logs() 查询历史。
所有 reveal/rotate/delete/auth/token 操作均应调用 record()。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import desc, select

from .db import session_scope
from .models import AuditAction, AuditLog


def record(
    action: AuditAction,
    actor: str,
    target: str | None = None,
    success: bool = True,
    detail: dict[str, Any] | None = None,
) -> None:
    """记录一条审计日志。失败不应抛异常（审计独立于业务）。"""
    try:
        with session_scope() as s:
            s.add(AuditLog(
                action=action,
                actor=actor,
                target=target,
                success=success,
                detail=detail or {},
                created_at=datetime.utcnow(),
            ))
    except Exception as e:  # noqa: BLE001
        # 审计写入失败不应影响主流程，仅打印告警
        print(f"[audit] failed to record {action.value}: {e}", flush=True)


def list_logs(
    limit: int = 100,
    action: AuditAction | None = None,
    target: str | None = None,
    success_only: bool | None = None,
) -> list[dict[str, Any]]:
    """查询审计日志，返回 dict 列表（便于序列化）。"""
    with session_scope() as s:
        stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if target:
            stmt = stmt.where(AuditLog.target == target)
        if success_only is not None:
            stmt = stmt.where(AuditLog.success == success_only)
        rows = s.execute(stmt).scalars().all()
        return [
            {
                "id": r.id,
                "action": r.action.value,
                "actor": r.actor,
                "target": r.target,
                "success": r.success,
                "detail": r.detail or {},
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]


def cleanup_old_logs(retention_days: int) -> int:
    """清理超过保留期的审计日志。返回删除的条数。"""
    if retention_days <= 0:
        return 0
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    from sqlalchemy import delete
    with session_scope() as s:
        result = s.execute(
            delete(AuditLog).where(AuditLog.created_at < cutoff)
        )
        return result.rowcount or 0
