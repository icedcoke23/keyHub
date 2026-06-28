"""备份导出/导入。

格式：.khbak 文件 = 版本头 + Argon2 参数 + AES-256-GCM 加密的 JSON payload。

- 导出密码独立于主密码，便于把备份交给不同保管人
- 备份内容含所有凭证（含明文）+ LLM key 扩展，不含 API Token（避免明文 token 落盘）
- 导入时凭证按 name 去重：同名则跳过（除非 --overwrite）

文件结构（二进制，大端）：
  magic(4) "KHBP" | version(1) | argon2_params_len(4) | argon2_params_json | nonce(12) | ciphertext
"""

from __future__ import annotations

import json
import os
import struct
from datetime import datetime
from typing import Any

from sqlalchemy import select

from .crypto import (
    AESGCM,
    Argon2Params,
    derive_master_key,
    new_argon2_params,
)
from .db import session_scope
from .models import Credential, LLMKey
from .runtime import get_runtime

_MAGIC = b"KHBP"
_VERSION = 1


def export_backup(output_path: str, backup_password: str) -> dict[str, Any]:
    """导出所有凭证到加密备份文件。返回统计信息。"""
    rt = get_runtime()
    if not rt.unlocked:
        raise RuntimeError("KeyHub must be unlocked to export")

    # 收集所有凭证（含明文）
    items: list[dict[str, Any]] = []
    with session_scope() as s:
        creds = s.execute(
            select(Credential).where(Credential.deleted == False)  # noqa: E712
        ).scalars().all()
        for c in creds:
            plaintext = rt.vault.decrypt(c.encrypted_value)
            item = {
                "name": c.name,
                "type": c.type.value,
                "value": plaintext,
                "metadata": c.metadata_ or {},
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                "rotation_days": c.rotation_days,
                "last_rotated_at": c.last_rotated_at.isoformat() if c.last_rotated_at else None,
            }
            if c.llm_key:
                item["llm"] = {
                    "provider": c.llm_key.provider,
                    "label": c.llm_key.label,
                    "allowed_models": c.llm_key.allowed_models or [],
                    "priority": c.llm_key.priority,
                }
            items.append(item)

    payload = {
        "version": _VERSION,
        "exported_at": datetime.utcnow().isoformat(),
        "count": len(items),
        "credentials": items,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # 用备份密码派生密钥并加密
    params = new_argon2_params(time_cost=2, memory_cost=32768, parallelism=2)
    key = derive_master_key(backup_password, params)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, payload_bytes, associated_data=None)

    # 序列化文件
    params_json = json.dumps(params.to_dict()).encode("utf-8")
    with open(output_path, "wb") as f:
        f.write(_MAGIC)
        f.write(struct.pack(">B", _VERSION))
        f.write(struct.pack(">I", len(params_json)))
        f.write(params_json)
        f.write(nonce)
        f.write(ct)

    # 审计
    from .audit import record as audit_record
    from .models import AuditAction
    audit_record(AuditAction.backup_export, "master",
                 detail={"count": len(items), "path": output_path})

    return {"count": len(items), "path": output_path}


def import_backup(input_path: str, backup_password: str, *, overwrite: bool = False) -> dict[str, Any]:
    """从加密备份文件导入凭证。返回统计信息。"""
    rt = get_runtime()
    if not rt.unlocked:
        raise RuntimeError("KeyHub must be unlocked to import")

    with open(input_path, "rb") as f:
        magic = f.read(4)
        if magic != _MAGIC:
            raise ValueError("not a KeyHub backup file (bad magic)")
        version = struct.unpack(">B", f.read(1))[0]
        if version != _VERSION:
            raise ValueError(f"unsupported backup version: {version}")
        params_len = struct.unpack(">I", f.read(4))[0]
        params_json = f.read(params_len).decode("utf-8")
        nonce = f.read(12)
        ct = f.read()

    params = Argon2Params.from_dict(json.loads(params_json))
    key = derive_master_key(backup_password, params)
    aes = AESGCM(key)
    try:
        payload_bytes = aes.decrypt(nonce, ct, associated_data=None)
    except Exception:
        raise ValueError("wrong backup password or corrupted file")
    payload = json.loads(payload_bytes.decode("utf-8"))

    # 导入凭证
    from .models import CredentialType
    from .schemas import CredentialCreate
    from .store import create_credential

    imported = skipped = overwritten = 0
    for item in payload.get("credentials", []):
        name = item["name"]
        # 检查是否已存在（仅未软删除的）
        with session_scope() as s:
            existing = s.execute(
                select(Credential).where(Credential.name == name)
                .where(Credential.deleted == False)  # noqa: E712
            ).scalar_one_or_none()
            existing_id = existing.id if existing else None
            # 也清理同名但已软删除的旧行，避免 unique 约束冲突
            stale = s.execute(
                select(Credential).where(Credential.name == name)
                .where(Credential.deleted == True)  # noqa: E712
            ).scalars().all()
            for st in stale:
                s.delete(st)
        if existing_id and not overwrite:
            skipped += 1
            continue
        if existing_id and overwrite:
            # 硬删除已有同名凭证（关联的 LLMKey/RotationLog 由 cascade 处理）
            with session_scope() as s:
                row = s.get(Credential, existing_id)
                if row:
                    s.delete(row)

        llm = item.get("llm")
        create_credential(
            CredentialCreate(
                name=name,
                type=CredentialType(item["type"]),
                value=item["value"],
                metadata=item.get("metadata", {}),
                provider=llm["provider"] if llm else None,
                label=llm["label"] if llm else None,
                allowed_models=llm.get("allowed_models", []) if llm else [],
                priority=llm.get("priority", 0) if llm else 0,
                rotation_days=item.get("rotation_days"),
            ),
            actor="backup.import",
        )
        if existing_id and overwrite:
            overwritten += 1
        else:
            imported += 1

    # 审计
    from .audit import record as audit_record
    from .models import AuditAction
    audit_record(AuditAction.backup_import, "master",
                 detail={"path": input_path, "imported": imported,
                         "skipped": skipped, "overwritten": overwritten})

    return {
        "imported": imported,
        "skipped": skipped,
        "overwritten": overwritten,
        "total_in_backup": payload.get("count", 0),
    }
