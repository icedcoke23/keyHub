"""健康检查与系统状态路由。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import Response

from ..auth import require_scope
from ..notify import get_notifier
from ..runtime import get_runtime

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/status")
def status():
    rt = get_runtime()
    s = rt.status()
    return {
        "initialized": s.initialized,
        "locked": s.locked,
        "unlocked": rt.unlocked,
    }


@router.post("/notify/test")
def test_notify(_: str = Depends(require_scope("admin:write"))):
    get_notifier().notify("test.notification", {"message": "test from KeyHub API"})
    return {"message": "notification sent"}


@router.post("/backup/encrypted")
def encrypted_backup(
    password: str = Form(...),
    _: str = Depends(require_scope("admin:write")),
):
    from ..backup import export_encrypted_backup
    try:
        data = export_encrypted_backup(password)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"backup failed: {e}")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=keyhub-backup.khbk"},
    )


@router.post("/restore/encrypted")
async def encrypted_restore(
    password: str = Form(...),
    file: UploadFile = File(...),
    _: str = Depends(require_scope("admin:write")),
):
    from ..backup import import_encrypted_backup
    try:
        data = await file.read()
        count = import_encrypted_backup(data, password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"restore failed: {e}")
    return {"message": "restore completed", "credentials_count": count}
