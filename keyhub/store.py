"""凭证存储业务逻辑：CRUD、解密、轮换。"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from sqlalchemy import select

from .db import session_scope
from .models import (
    Credential,
    CredentialType,
    LLMKey,
    LLMKeyStatus,
    RotationLog,
)
from .runtime import get_runtime
from .schemas import (
    CredentialCreate,
    CredentialOut,
    CredentialSecret,
    CredentialUpdate,
)


def _encrypt(value: str) -> bytes:
    return get_runtime().vault.encrypt(value)


def _decrypt(blob: bytes) -> str:
    return get_runtime().vault.decrypt(blob)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _to_out(c: Credential) -> CredentialOut:
    out = CredentialOut(
        id=c.id,
        name=c.name,
        type=c.type,
        metadata=c.metadata_ or {},
        expires_at=c.expires_at,
        rotation_days=c.rotation_days,
        created_at=c.created_at,
        updated_at=c.updated_at,
        last_rotated_at=c.last_rotated_at,
    )
    if c.llm_key:
        out.provider = c.llm_key.provider
        out.label = c.llm_key.label
        out.llm_status = c.llm_key.status
        out.total_requests = c.llm_key.total_requests
        out.estimated_cost_usd = c.llm_key.estimated_cost_usd
    return out


# ===== 创建 =====

def create_credential(data: CredentialCreate) -> CredentialOut:
    with session_scope() as s:
        existing = s.execute(
            select(Credential).where(Credential.name == data.name)
        ).scalar_one_or_none()
        if existing:
            raise ValueError(f"credential '{data.name}' already exists")

        cred = Credential(
            name=data.name,
            type=data.type,
            encrypted_value=_encrypt(data.value),
            metadata_=data.metadata,
            expires_at=data.expires_at,
            rotation_days=data.rotation_days,
        )
        s.add(cred)

        if data.type == CredentialType.llm:
            if not data.provider:
                raise ValueError("LLM credential requires 'provider'")
            label = data.label or data.name
            llm = LLMKey(
                credential=cred,
                provider=data.provider,
                label=label,
                allowed_models=data.allowed_models,
                priority=data.priority,
                status=LLMKeyStatus.active,
            )
            s.add(llm)

        s.flush()
        s.refresh(cred)
        return _to_out(cred)


# ===== 列表 =====

def list_credentials(
    type_filter: CredentialType | None = None,
    include_deleted: bool = False,
) -> list[CredentialOut]:
    with session_scope() as s:
        stmt = select(Credential)
        if not include_deleted:
            stmt = stmt.where(Credential.deleted == False)  # noqa: E712
        if type_filter:
            stmt = stmt.where(Credential.type == type_filter)
        stmt = stmt.order_by(Credential.name)
        rows = s.execute(stmt).scalars().all()
        return [_to_out(c) for c in rows]


# ===== 详情（不含明文） =====

def get_credential(name: str) -> CredentialOut:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        return _to_out(c)


# ===== 取明文 =====

def reveal_credential(name: str) -> CredentialSecret:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        value = _decrypt(c.encrypted_value)
        return CredentialSecret(
            id=c.id,
            name=c.name,
            type=c.type,
            value=value,
            metadata=c.metadata_ or {},
        )


# ===== 更新 / 轮换 =====

def update_credential(name: str, data: CredentialUpdate) -> CredentialOut:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)

        old_fp = None
        rotated = False
        if data.value is not None:
            # 轮换：记录旧值指纹 + 写入新值
            try:
                old_value = _decrypt(c.encrypted_value)
                old_fp = _fingerprint(old_value)
            except Exception:
                old_fp = None
            c.encrypted_value = _encrypt(data.value)
            c.last_rotated_at = datetime.utcnow()
            rotated = True
        if data.metadata is not None:
            c.metadata_ = data.metadata
        if data.expires_at is not None:
            c.expires_at = data.expires_at
        if data.rotation_days is not None:
            c.rotation_days = data.rotation_days

        if rotated:
            s.add(RotationLog(
                credential=c,
                old_fingerprint=old_fp,
                note=data.rotation_note or "manual rotation",
            ))

        s.flush()
        s.refresh(c)
        return _to_out(c)


def rotate_credential(name: str, new_value: str, note: str | None = None) -> CredentialOut:
    return update_credential(name, CredentialUpdate(
        value=new_value,
        rotation_note=note or "manual rotation",
    ))


# ===== 删除（软删除） =====

def delete_credential(name: str) -> None:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        c.deleted = True
