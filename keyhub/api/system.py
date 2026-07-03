"""健康检查与系统状态路由。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import Response

from ..audit import record as audit_record
from ..auth import require_scope
from ..models import AuditAction
from ..notify import get_notifier
from ..runtime import get_runtime

router = APIRouter(prefix="/api/system", tags=["system"])

logger = logging.getLogger(__name__)


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/status")
def status():
    """系统状态。仅返回 initialized（供前端决定渲染初始化页/解锁页）。

    locked/unlocked 属于敏感运行时状态，不再向未认证方泄漏。
    """
    rt = get_runtime()
    return {"initialized": rt.is_initialized()}


@router.post("/notify/test")
def test_notify(actor: str = Depends(require_scope("admin:write"))):
    get_notifier().notify("test.notification", {"message": "test from KeyHub API"})
    audit_record(AuditAction.system_notify_test, actor, target="notify.test",
                 detail={"reason": "test notification"})
    return {"message": "notification sent"}


@router.post("/backup/encrypted")
def encrypted_backup(
    password: str = Form(...),
    actor: str = Depends(require_scope("admin:write")),
):
    from ..backup import export_encrypted_backup
    try:
        data = export_encrypted_backup(password, actor=actor)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception:
        logger.exception("encrypted backup export failed")
        raise HTTPException(500, "backup failed: internal error")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=keyhub-backup.khbk"},
    )


@router.post("/restore/encrypted")
async def encrypted_restore(
    password: str = Form(...),
    file: UploadFile = File(...),
    actor: str = Depends(require_scope("admin:write")),
):
    from ..backup import import_encrypted_backup
    try:
        data = await file.read()
        count = import_encrypted_backup(data, password, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception:
        logger.exception("encrypted restore failed")
        raise HTTPException(500, "restore failed: internal error")
    return {"message": "restore completed", "credentials_count": count}
