"""认证模块：主密码登录 + API Token + Session Cookie。"""

from __future__ import annotations

import hashlib
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .models import APIToken
from .runtime import get_runtime

# Session Cookie 名称
SESSION_COOKIE = "keyhub_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 天

_bearer = HTTPBearer(auto_error=False)


def _serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.ensure_secret_key(), salt="keyhub-session")


# ===== Session =====

def create_session(subject: str) -> str:
    """subject 通常为 'master'。"""
    return _serializer().dumps({"sub": subject})


def verify_session(token: str) -> bool:
    try:
        _serializer().loads(token, max_age=SESSION_MAX_AGE)
        return True
    except BadSignature:
        return False


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
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
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


def require_auth(
    request: Request,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
) -> str:
    """认证依赖：优先 API Token，其次 Session Cookie。

    返回认证主体标识（'master' 或 token id）。
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
        return f"token:{row.id}"

    # 2) Session cookie
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie and verify_session(cookie):
        return "master"

    raise HTTPException(
        status_code=401,
        detail="not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
