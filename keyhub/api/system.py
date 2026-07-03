"""健康检查与系统状态路由。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import Response

from ..auth import require_scope
from ..notify import get_notifier
from ..runtime import get_runtime
from ..structured_logging import safe_detail

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/status")
def status():
    """返回金库初始化状态（公开端点）。

    仅返回 initialized 布尔值：前端据此决定渲染初始化页还是解锁页。
    不暴露 locked/unlocked 状态——这些属于运行时敏感信息，
    未认证调用方无需得知金库当前是否已解锁。已认证调用方可通过
    API 调用是否返回 401 自行推断锁定状态。
    """
    rt = get_runtime()
    s = rt.status()
    return {"initialized": s.initialized}


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
        # 不向客户端泄漏内部异常详情（可能含路径/堆栈/密钥材料）
        raise HTTPException(500, safe_detail(e, "backup failed"))
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
        # 不向客户端泄漏内部异常详情
        raise HTTPException(500, safe_detail(e, "restore failed"))
    return {"message": "restore completed", "credentials_count": count}
