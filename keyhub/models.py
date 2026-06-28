"""SQLAlchemy ORM 模型。

表设计：
- kv_store       : 系统级键值（argon2 参数、主密码哈希等）
- credentials    : 凭证主表（含常规密码与 LLM key 通用字段）
- llm_keys       : LLM key 扩展信息（供应商、配额、状态、用量汇总）
- usage_logs     : LLM 调用明细（每次代理请求一条）
- rotation_log   : 凭证轮换历史
- api_tokens     : 程序化访问 Token（可吊销）
- audit_logs     : 安全审计日志（reveal/rotate/delete 等敏感操作）
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    """Naive UTC datetime — 与 SQLite 存储一致，避免 aware/naive 比较错误。"""
    return datetime.utcnow()


def _uuid() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


# ===== 系统键值表 =====

class KVStore(Base):
    __tablename__ = "kv_store"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)


# ===== 凭证类型枚举 =====

class CredentialType(str, enum.Enum):
    password = "password"   # 常规密码 / Web 登录
    token = "token"         # 通用 API Token
    ssh_key = "ssh_key"     # SSH 私钥
    database = "database"   # 数据库连接串
    llm = "llm"             # 大模型 API Key（关联 llm_keys）
    other = "other"


# ===== 凭证主表 =====

class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    type: Mapped[CredentialType] = mapped_column(Enum(CredentialType), nullable=False, index=True)

    # 加密后的凭证值（AES-256-GCM: nonce || ciphertext）
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # 元信息（不加密，但不含敏感数据）：URL、用户名、备注等
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    # 过期与轮换
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    rotation_days: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 建议轮换周期

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 软删除
    deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # LLM 扩展（仅 type==llm 时使用）
    llm_key: Mapped["LLMKey | None"] = relationship(
        back_populates="credential",
        cascade="all, delete-orphan",
        uselist=False,
    )
    rotations: Mapped[list["RotationLog"]] = relationship(
        back_populates="credential",
        cascade="all, delete-orphan",
        order_by="RotationLog.rotated_at.desc()",
    )


# ===== LLM Key 扩展 =====

class LLMKeyStatus(str, enum.Enum):
    active = "active"
    disabled = "disabled"      # 手动停用
    rate_limited = "rate_limited"  # 被限流，冷却中
    exhausted = "exhausted"    # 配额耗尽
    error = "error"


class LLMKey(Base):
    __tablename__ = "llm_keys"
    __table_args__ = (
        UniqueConstraint("provider", "label", name="uq_llm_provider_label"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.id", ondelete="CASCADE"), unique=True, nullable=False
    )

    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # 同一 provider 下的标签，用于负载均衡分组内标识
    label: Mapped[str] = mapped_column(String(64), nullable=False)

    # 该 key 允许使用的模型列表（空表示不限制）
    allowed_models: Mapped[list] = mapped_column(JSON, default=list)

    # 限流与冷却
    status: Mapped[LLMKeyStatus] = mapped_column(
        Enum(LLMKeyStatus), default=LLMKeyStatus.active, index=True
    )
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 优先级：数值越大越优先；同优先级轮询
    priority: Mapped[int] = mapped_column(Integer, default=0)

    # 用量汇总（增量更新）
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    total_prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    credential: Mapped[Credential] = relationship(back_populates="llm_key")
    usage_logs: Mapped[list["UsageLog"]] = relationship(
        back_populates="llm_key", cascade="all, delete-orphan"
    )


# ===== LLM 调用明细 =====

class UsageLog(Base):
    __tablename__ = "usage_logs"
    __table_args__ = (
        Index("ix_usage_llm_time", "llm_key_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    llm_key_id: Mapped[str] = mapped_column(
        ForeignKey("llm_keys.id", ondelete="CASCADE"), nullable=False, index=True
    )

    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)

    llm_key: Mapped[LLMKey] = relationship(back_populates="usage_logs")


# ===== 轮换历史 =====

class RotationLog(Base):
    __tablename__ = "rotation_log"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rotated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 旧值的指纹（SHA256 前 8 位），用于审计比对，不含明文
    old_fingerprint: Mapped[str | None] = mapped_column(String(16), nullable=True)

    credential: Mapped[Credential] = relationship(back_populates="rotations")


# ===== API Token（程序化访问） =====

class APIToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # token_hash = sha256(token) 的 hex，明文 token 仅在创建时返回一次
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scopes: Mapped[list] = mapped_column(JSON, default=lambda: ["*"])  # ["credentials:read", ...]

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


# ===== 审计日志 =====

class AuditAction(str, enum.Enum):
    # 凭证操作
    credential_create = "credential.create"
    credential_reveal = "credential.reveal"      # 读取明文（敏感）
    credential_update = "credential.update"
    credential_rotate = "credential.rotate"
    credential_delete = "credential.delete"
    # 认证
    auth_unlock = "auth.unlock"
    auth_lock = "auth.lock"
    auth_unlock_failed = "auth.unlock_failed"
    auth_init = "auth.init"
    auth_password_change = "auth.password_change"
    # Token
    token_create = "token.create"
    token_revoke = "token.revoke"
    # 系统
    backup_export = "backup.export"
    backup_import = "backup.import"
    llm_proxy_call = "llm.proxy_call"


class AuditLog(Base):
    """安全审计日志。

    记录所有敏感操作（who / when / what / result）。
    不记录凭证明文，但记录操作目标（如凭证名）与结果。
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_action_time", "action", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    # 操作类型
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False, index=True)
    # 操作主体：'master' 或 'token:<id>'
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    # 操作目标（如凭证名、token 名），可空
    target: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    # 结果：success / failure
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    # 详细信息（JSON，不含明文），如 IP、错误原因等
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
