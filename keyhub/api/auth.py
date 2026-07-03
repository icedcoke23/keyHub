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
    require_scope,
)
from ..config import get_settings
from ..db import session_scope
from ..models import APIToken, AuditAction
from ..ratelimit import get_limiter
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
    """获取真实客户端 IP，基于 trusted_proxy_depth + trusted_proxy_ips 配置。

    防止伪造 XFF 绕过 IP 限流：
    - depth=0：完全不信任 XFF，用 request.client.host
    - depth=N 且配置了 trusted_proxy_ips：仅当直连对端 IP 在白名单内才解析 XFF
    - depth=N 且未配置白名单：仅按 depth 取 XFF 倒数第 N 跳（向后兼容）
    """
    settings = get_settings()
    depth = settings.trusted_proxy_depth
    peer = request.client.host if request.client else "unknown"

    if depth > 0:
        # 若配置了反代 IP 白名单，先校验直连对端是否可信
        whitelist_str = settings.trusted_proxy_ips
        if whitelist_str:
            whitelist = {ip.strip() for ip in whitelist_str.split(",") if ip.strip()}
            if peer not in whitelist:
                # 直连对端不在白名单，不信任 XFF，防伪造
                return peer
        xff = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= depth:
            return parts[-depth]
    return peer


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
    """解锁并建立 session。

    含基于 IP 的失败限流：连续失败达阈值后锁定该 IP（指数退避）。
    """
    rt = get_runtime()
    if not rt.is_initialized():
        raise HTTPException(400, "not initialized")
    ip = _client_ip(request)
    # 限流检查
    limiter = get_limiter()
    locked, remaining = limiter.is_locked(ip)
    if locked:
        audit_record(AuditAction.auth_unlock_failed, "anonymous",
                     success=False, detail={"ip": ip, "reason": "rate_limited",
                                            "retry_after": remaining})
        raise HTTPException(429, f"too many failed attempts; retry after {remaining}s")
    if not rt.unlock(body.password):
        # 解锁失败必须审计 + 计入限流
        audit_record(AuditAction.auth_unlock_failed, "anonymous",
                     success=False, detail={"ip": ip})
        triggered, lock_secs = limiter.record_failure(ip)
        if triggered:
            raise HTTPException(429, f"too many failed attempts; locked for {lock_secs}s")
        raise HTTPException(401, "invalid master password")
    # 成功：重置限流计数
    limiter.record_success(ip)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session("master"),
        httponly=True,
        samesite="strict",
        secure=get_settings().is_prod,
        max_age=7 * 24 * 3600,
    )
    audit_record(AuditAction.auth_unlock, "master",
                 detail={"ip": ip})
    return MessageOut(message="unlocked")


@router.post("/lock", response_model=MessageOut)
def lock(actor: str = Depends(require_scope("admin:write"))):
    get_runtime().lock()
    audit_record(AuditAction.auth_lock, actor)
    return MessageOut(message="locked")


@router.post("/change-password", response_model=MessageOut)
def change_password(body: ChangePasswordRequest, actor: str = Depends(require_scope("admin:write"))):
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
def create_api_token(body: TokenCreate, actor: str = Depends(require_scope("admin:write"))):
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
def list_tokens(_: str = Depends(require_scope("admin:read"))):
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
def revoke_token(token_id: str, actor: str = Depends(require_scope("admin:write"))):
    with session_scope() as s:
        r = s.get(APIToken, token_id)
        if r is None:
            raise HTTPException(404, "token not found")
        r.revoked = True
        name = r.name
    audit_record(AuditAction.token_revoke, actor, target=name,
                 detail={"token_id": token_id})
    return MessageOut(message="revoked")
