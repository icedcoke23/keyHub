"""凭证存储业务逻辑：CRUD、解密、轮换、版本历史。"""

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
    RotationLogOut,
)


def _encrypt(value: str, aad: bytes | None = None) -> bytes:
    return get_runtime().encrypt(value, aad=aad)


def _decrypt(blob: bytes, aad: bytes | None = None) -> str:
    return get_runtime().decrypt(blob, aad=aad)


def _make_aad(cred_id: str, name: str) -> bytes:
    return f"{cred_id}:{name}".encode("utf-8")


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
        tags=c.tags or [],
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


def _try_decrypt(c: Credential) -> str:
    """解密凭证值，自动尝试 v0（无AAD）和 v1（有AAD）格式。"""
    aad = _make_aad(c.id, c.name)
    try:
        return _decrypt(c.encrypted_value, aad=aad)
    except Exception:
        try:
            return _decrypt(c.encrypted_value, aad=None)
        except Exception:
            return _decrypt(c.encrypted_value)


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
            encrypted_value=b"",
            metadata_=data.metadata,
            expires_at=data.expires_at,
            rotation_days=data.rotation_days,
            tags=data.tags or [],
        )
        s.add(cred)
        s.flush()

        cred.encrypted_value = _encrypt(data.value, aad=_make_aad(cred.id, cred.name))

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
            stmt = stmt.where(Credential.name.contains(q))
        if tag:
            stmt = stmt.where(text("tags LIKE '%' || :tag || '%'").bindparams(tag=tag))
        stmt = stmt.order_by(Credential.name)
        rows = s.execute(stmt).scalars().all()
        return [_to_out(c) for c in rows]


def get_credential(name: str) -> CredentialOut:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
            .where(Credential.deleted == False)  # noqa: E712
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        return _to_out(c)


def reveal_credential(name: str, actor: str = "system") -> CredentialSecret:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
            .where(Credential.deleted == False)  # noqa: E712
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        value = _try_decrypt(c)
        out = CredentialSecret(
            id=c.id,
            name=c.name,
            type=c.type,
            value=value,
            metadata=c.metadata_ or {},
            tags=c.tags or [],
        )
    audit_record(AuditAction.credential_reveal, actor, target=name,
                 detail={"type": out.type.value})
    return out


def update_credential(name: str, data: CredentialUpdate, actor: str = "system") -> CredentialOut:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)

        old_fp = None
        old_encrypted = None
        rotated = False
        if data.value is not None:
            try:
                old_value = _try_decrypt(c)
                old_fp = _fingerprint(old_value)
            except Exception:
                old_fp = None
            old_encrypted = c.encrypted_value
            c.encrypted_value = _encrypt(data.value, aad=_make_aad(c.id, c.name))
            c.last_rotated_at = datetime.utcnow()
            rotated = True
        if data.metadata is not None:
            c.metadata_ = data.metadata
        if data.expires_at is not None:
            c.expires_at = data.expires_at
        if data.rotation_days is not None:
            c.rotation_days = data.rotation_days
        if data.tags is not None:
            c.tags = data.tags

        if rotated:
            s.add(RotationLog(
                credential=c,
                old_fingerprint=old_fp,
                encrypted_value=old_encrypted,
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


def delete_credential(name: str, actor: str = "system") -> None:
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        c.deleted = True
    audit_record(AuditAction.credential_delete, actor, target=name)


def reveal_raw(cred_id: str, encrypted_value: bytes, cred_name: str) -> str:
    """LLM 代理等内部调用：直接解密 LLM key 的明文。"""
    aad = _make_aad(cred_id, cred_name)
    try:
        return _decrypt(encrypted_value, aad=aad)
    except Exception:
        try:
            return _decrypt(encrypted_value, aad=None)
        except Exception:
            return _decrypt(encrypted_value)


def get_credential_history(name: str) -> list[RotationLogOut]:
    """返回某凭证的轮换历史列表（不含密文，仅元信息）。"""
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)
        logs = s.execute(
            select(RotationLog)
            .where(RotationLog.credential_id == c.id)
            .order_by(RotationLog.rotated_at.desc())
        ).scalars().all()
        return [
            RotationLogOut(
                id=log.id,
                credential_id=log.credential_id,
                rotated_at=log.rotated_at,
                note=log.note,
                old_fingerprint=log.old_fingerprint,
            )
            for log in logs
        ]


def rollback_credential(name: str, rotation_id: str, actor: str = "system") -> CredentialOut:
    """将凭证值回滚到指定轮换版本。"""
    with session_scope() as s:
        c = s.execute(
            select(Credential).where(Credential.name == name)
        ).scalar_one_or_none()
        if c is None:
            raise KeyError(name)

        target_log = s.execute(
            select(RotationLog)
            .where(RotationLog.id == rotation_id)
            .where(RotationLog.credential_id == c.id)
        ).scalar_one_or_none()
        if target_log is None:
            raise KeyError(f"rotation log '{rotation_id}' not found")
        if target_log.encrypted_value is None:
            raise ValueError("cannot rollback: this version has no stored encrypted value")

        current_fp = None
        try:
            current_value = _try_decrypt(c)
            current_fp = _fingerprint(current_value)
        except Exception:
            current_fp = None

        current_encrypted = c.encrypted_value
        c.encrypted_value = target_log.encrypted_value
        c.last_rotated_at = datetime.utcnow()

        s.add(RotationLog(
            credential=c,
            old_fingerprint=current_fp,
            encrypted_value=current_encrypted,
            note=f"rollback to rotation {rotation_id}",
        ))

        s.flush()
        s.refresh(c)
        out = _to_out(c)

    audit_record(
        AuditAction.credential_rollback,
        actor,
        target=name,
        detail={"rotation_id": rotation_id, "old_fingerprint": current_fp},
    )
    return out
