"""凭证存储业务逻辑：CRUD、解密、轮换。"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from sqlalchemy import select, text

from .audit import record as audit_record
from .db import session_scope
from .models import (
    AuditAction,
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
        tags=c.tags or [],
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
        out.monthly_budget_usd = c.llm_key.monthly_budget_usd
        out.avg_latency_ms = c.llm_key.avg_latency_ms
    return out


# ===== 创建 =====

def create_credential(data: CredentialCreate, actor: str = "system") -> CredentialOut:
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
            tags=data.tags,
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
                weight=data.weight,
                monthly_budget_usd=data.monthly_budget_usd,
                status=LLMKeyStatus.active,
            )
            s.add(llm)

        s.flush()
        s.refresh(cred)
        out = _to_out(cred)
    audit_record(AuditAction.credential_create, actor, target=data.name,
                 detail={"type": data.type.value})
    return out


# ===== 列表 =====

def list_credentials(
    type_filter: CredentialType | None = None,
    include_deleted: bool = False,
    q: str | None = None,
    tag: str | None = None,
) -> list[CredentialOut]:
    with session_scope() as s:
        stmt = select(Credential)
        if not include_deleted:
            stmt = stmt.where(Credential.deleted == False)  # noqa: E712
        if type_filter:
            stmt = stmt.where(Credential.type == type_filter)
        if q:
            # 搜索 name 和 metadata 中的 JSON 文本
            stmt = stmt.where(Credential.name.contains(q))
        if tag:
            # SQLite JSON 数组包含检查
            stmt = stmt.where(text("tags LIKE '%' || :tag || '%'").bindparams(tag=tag))
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

def reveal_credential(name: str, actor: str = "system") -> CredentialSecret:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        value = _decrypt(c.encrypted_value)
        out = CredentialSecret(
            id=c.id,
            name=c.name,
            type=c.type,
            value=value,
            metadata=c.metadata_ or {},
            tags=c.tags or [],
        )
    # reveal 是最敏感的操作，必须审计；记录目标与类型，不记录明文
    audit_record(AuditAction.credential_reveal, actor, target=name,
                 detail={"type": out.type.value})
    return out


# ===== 更新 / 轮换 =====

def update_credential(name: str, data: CredentialUpdate, actor: str = "system") -> CredentialOut:
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
        if data.tags is not None:
            c.tags = data.tags
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
        out = _to_out(c)
    audit_record(
        AuditAction.credential_rotate if rotated else AuditAction.credential_update,
        actor, target=name,
        detail={"rotated": rotated, "old_fingerprint": old_fp} if rotated else {},
    )
    return out


def rotate_credential(name: str, new_value: str, note: str | None = None,
                      actor: str = "system") -> CredentialOut:
    return update_credential(name, CredentialUpdate(
        value=new_value,
        rotation_note=note or "manual rotation",
    ), actor=actor)


# ===== 删除（软删除） =====

def delete_credential(name: str, actor: str = "system") -> None:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        c.deleted = True
    audit_record(AuditAction.credential_delete, actor, target=name)
