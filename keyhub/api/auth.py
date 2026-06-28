"""认证路由：初始化、解锁、登录、API Token 管理。"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from ..audit import record as audit_record
from ..auth import (
    SESSION_COOKIE,
    create_session,
    create_token,
    hash_token,
    require_auth,
)
from ..config import get_settings
from ..db import session_scope
from ..models import APIToken, AuditAction
from ..runtime import get_runtime
from ..schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageOut,
    TokenCreate,
    TokenCreated,
    TokenOut,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    # 信任反向代理设置的 X-Forwarded-For
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/init", response_model=MessageOut)
def init(body: LoginRequest, request: Request):
    """首次初始化：设置主密码。"""
    rt = get_runtime()
    if rt.is_initialized():
        raise HTTPException(400, "already initialized")
    if len(body.password) < 8:
        raise HTTPException(400, "password too short (min 8 chars)")
    rt.initialize(body.password)
    audit_record(AuditAction.auth_init, "master",
                 detail={"ip": _client_ip(request)})
    return MessageOut(message="initialized")


@router.post("/unlock", response_model=MessageOut)
def unlock(body: LoginRequest, response: Response, request: Request):
    """解锁并建立 session。"""
    rt = get_runtime()
    if not rt.is_initialized():
        raise HTTPException(400, "not initialized")
    if not rt.unlock(body.password):
        # 解锁失败必须审计
        audit_record(AuditAction.auth_unlock_failed, "anonymous",
                     success=False, detail={"ip": _client_ip(request)})
        raise HTTPException(401, "invalid master password")
    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session("master"),
        httponly=True,
        samesite="strict",
        secure=get_settings().is_prod,
        max_age=7 * 24 * 3600,
    )
    audit_record(AuditAction.auth_unlock, "master",
                 detail={"ip": _client_ip(request)})
    return MessageOut(message="unlocked")


@router.post("/lock", response_model=MessageOut)
def lock(actor: str = Depends(require_auth)):
    get_runtime().lock()
    audit_record(AuditAction.auth_lock, actor)
    return MessageOut(message="locked")


@router.post("/change-password", response_model=MessageOut)
def change_password(body: ChangePasswordRequest, actor: str = Depends(require_auth)):
    """变更主密码（重新加密所有凭证）。

    要求当前已解锁。变更成功后旧 session 仍有效（vault 已热替换）。
    所有已签发 API Token 不受影响（token 哈希独立于主密码）。
    """
    rt = get_runtime()
    try:
        n = rt.change_master_password(body.old_password, body.new_password)
    except ValueError as e:
        audit_record(AuditAction.auth_password_change, actor,
                     success=False, detail={"reason": str(e)})
        raise HTTPException(400, str(e))
    audit_record(AuditAction.auth_password_change, actor,
                 detail={"reencrypted": n})
    return MessageOut(message=f"password changed; {n} credentials re-encrypted")


@router.post("/logout", response_model=MessageOut)
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return MessageOut(message="logged out")


# ===== API Token =====

@router.post("/tokens", response_model=TokenCreated)
def create_api_token(body: TokenCreate, actor: str = Depends(require_auth)):
    settings = get_settings()
    expires_in = body.expires_in_hours if body.expires_in_hours else settings.token_expire_hours
    raw, record = create_token(body.name, body.scopes, expires_in)
    audit_record(AuditAction.token_create, actor, target=body.name,
                 detail={"token_id": record.id, "scopes": body.scopes})
    return TokenCreated(
        id=record.id,
        name=record.name,
        scopes=record.scopes,
        created_at=record.created_at,
        expires_at=record.expires_at,
        last_used_at=record.last_used_at,
        revoked=record.revoked,
        token=raw,
    )


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(_: str = Depends(require_auth)):
    with session_scope() as s:
        rows = s.execute(select(APIToken).order_by(APIToken.created_at.desc())).scalars().all()
        return [
            TokenOut(
                id=r.id,
                name=r.name,
                scopes=r.scopes,
                created_at=r.created_at,
                expires_at=r.expires_at,
                last_used_at=r.last_used_at,
                revoked=r.revoked,
            )
            for r in rows
        ]


@router.delete("/tokens/{token_id}", response_model=MessageOut)
def revoke_token(token_id: str, actor: str = Depends(require_auth)):
    with session_scope() as s:
        r = s.get(APIToken, token_id)
        if r is None:
            raise HTTPException(404, "token not found")
        r.revoked = True
        name = r.name
    audit_record(AuditAction.token_revoke, actor, target=name,
                 detail={"token_id": token_id})
    return MessageOut(message="revoked")
