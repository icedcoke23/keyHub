"""认证模块：主密码登录 + API Token + Session Cookie。"""

from __future__ import annotations

import hashlib
import secrets as _secrets
from datetime import datetime, timedelta
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .models import APIToken, KVStore
from .runtime import get_runtime

# Session Cookie 名称
SESSION_COOKIE = "keyhub_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 天

# KVStore 中的会话纪元键。lock() / change_master_password() 时递增，
# verify_session 校验 cookie 中的 epoch 与当前值一致，实现服务端撤销：
# - 锁定后所有已签发 session 立即失效
# - 改密后所有旧 session 立即失效
_KV_SESSION_EPOCH = "session_epoch"

_bearer = HTTPBearer(auto_error=False)


def _serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.ensure_secret_key(), salt="keyhub-session")


def get_session_epoch() -> int:
    """读取当前会话纪元。"""
    with session_scope() as s:
        row = s.execute(
            select(KVStore).where(KVStore.key == _KV_SESSION_EPOCH)
        ).scalar_one_or_none()
        if row is None:
            return 0
        try:
            return int(row.value)
        except (ValueError, TypeError):
            return 0


def bump_session_epoch() -> int:
    """递增会话纪元，使所有已签发 session 失效。返回新纪元值。"""
    with session_scope() as s:
        row = s.execute(
            select(KVStore).where(KVStore.key == _KV_SESSION_EPOCH)
        ).scalar_one_or_none()
        if row is None:
            new_val = 1
            s.add(KVStore(key=_KV_SESSION_EPOCH, value=str(new_val)))
        else:
            try:
                new_val = int(row.value) + 1
            except (ValueError, TypeError):
                new_val = 1
            row.value = str(new_val)
        return new_val


# ===== Session =====

def create_session(subject: str) -> str:
    """subject 通常为 'master'。session 携带当前纪元，用于服务端撤销。"""
    epoch = get_session_epoch()
    return _serializer().dumps({"sub": subject, "ep": epoch})


def verify_session(token: str) -> bool:
    """校验 session 签名 + max_age + 纪元（服务端撤销）。"""
    try:
        payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return False
    # 校验纪元：lock()/change_password() 会递增纪元，使旧 session 失效
    cookie_epoch = payload.get("ep", -1)
    if cookie_epoch != get_session_epoch():
        return False
    return True


# ===== API Token =====

def generate_api_token() -> str:
    """生成明文 token: 'khub_' + 40 hex。仅创建时返回。"""
    return "khub_" + _secrets.token_hex(20)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(name: str, scopes: list[str], expires_in_hours: int | None) -> tuple[str, APIToken]:
    raw = generate_api_token()
    expires_at = None
    if expires_in_hours:
        # 统一使用 naive UTC，与 SQLite 存储 / 比较一致（避免 aware/naive TypeError）
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
    record = APIToken(
        name=name,
        token_hash=hash_token(raw),
        scopes=scopes,
        expires_at=expires_at,
    )
    with session_scope() as s:
        s.add(record)
        s.flush()
        s.refresh(record)
    return raw, record


# ===== 依赖项 =====

def _unlocked_or_401():
    rt = get_runtime()
    if not rt.unlocked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="KeyHub is locked; unlock with master password",
        )


def _scope_matches(required: str, granted: list[str]) -> bool:
    """校验 required scope 是否被 granted 列表覆盖。

    规则：
    - granted 含 "*" → 通配所有权限
    - granted 含 "admin:*" 或 "<prefix>:*" → 覆盖该前缀下所有 scope
    - 精确匹配 required
    """
    for g in granted:
        if g == "*":
            return True
        if g == required:
            return True
        if g.endswith(":*") and required.startswith(g[:-1]):
            return True
    return False


def require_auth(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
    required_scope: str | None = None,
) -> str:
    """认证依赖：优先 API Token，其次 Session Cookie。

    返回认证主体标识（'master' 或 token id）。

    Session 认证（浏览器登录）默认拥有全部权限。
    API Token 认证需校验 required_scope（若提供）。
    """
    rt = get_runtime()
    if not rt.is_initialized():
        raise HTTPException(status_code=503, detail="KeyHub not initialized")
    _unlocked_or_401()

    # 1) Bearer token
    if creds and creds.credentials:
        token = creds.credentials
        h = hash_token(token)
        with session_scope() as s:
            row = s.execute(
                select(APIToken).where(APIToken.token_hash == h)
            ).scalar_one_or_none()
            if row is None or row.revoked:
                raise HTTPException(status_code=401, detail="invalid token")
            if row.expires_at and row.expires_at < datetime.utcnow():
                raise HTTPException(status_code=401, detail="token expired")
            row.last_used_at = datetime.utcnow()
            token_scopes = list(row.scopes or [])
        # scope 校验
        if required_scope and not _scope_matches(required_scope, token_scopes):
            raise HTTPException(
                status_code=403,
                detail=f"token lacks required scope: {required_scope}",
            )
        # 速率限制检查
        from .ratelimit import get_token_limiter
        from .models import AuditAction
        from .audit import record as audit_record
        allowed, remaining = get_token_limiter().check(row.id)
        if not allowed:
            audit_record(
                AuditAction.token_rate_limited,
                f"token:{row.id}",
                success=False,
                detail={"reason": "rpm exceeded"},
            )
            raise HTTPException(
                status_code=429,
                detail="token rate limit exceeded",
                headers={"Retry-After": "60"},
            )
        from .auto_lock import get_auto_lock_checker
        get_auto_lock_checker().touch()
        return f"token:{row.id}"

    # 2) Session cookie（浏览器登录，拥有全部权限）
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie and verify_session(cookie):
        from .auto_lock import get_auto_lock_checker
        get_auto_lock_checker().touch()
        return "master"

    raise HTTPException(
        status_code=401,
        detail="not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scope(scope: str):
    """工厂依赖：生成要求指定 scope 的认证依赖。

    用法：actor: str = Depends(require_scope("credentials:reveal"))
    Session 认证总是通过；API Token 必须具备该 scope（或通配）。
    """
    def _dep(
        request: Request,
        creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
    ) -> str:
        return require_auth(request, creds, required_scope=scope)
    return _dep
