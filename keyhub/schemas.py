"""Pydantic 请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .models import CredentialType, LLMKeyStatus


# ===== 凭证 =====

class CredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    type: CredentialType = CredentialType.password
    value: str = Field(..., min_length=1)  # 明文，仅用于加密入库
    metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None
    rotation_days: int | None = None
    # LLM 扩展
    provider: str | None = None
    label: str | None = None
    allowed_models: list[str] = Field(default_factory=list)
    priority: int = 0


class CredentialUpdate(BaseModel):
    value: str | None = None
    metadata: dict[str, Any] | None = None
    expires_at: datetime | None = None
    rotation_days: int | None = None
    rotation_note: str | None = None


class CredentialOut(BaseModel):
    id: str
    name: str
    type: CredentialType
    metadata: dict[str, Any]
    expires_at: datetime | None
    rotation_days: int | None
    created_at: datetime
    updated_at: datetime
    last_rotated_at: datetime | None
    # LLM 扩展（若存在）
    provider: str | None = None
    label: str | None = None
    llm_status: LLMKeyStatus | None = None
    total_requests: int | None = None
    estimated_cost_usd: float | None = None


class CredentialSecret(BaseModel):
    """含明文的响应（仅在显式 get 时返回）。"""

    id: str
    name: str
    type: CredentialType
    value: str
    metadata: dict[str, Any]


# ===== LLM 用量 =====

class UsageOut(BaseModel):
    id: str
    llm_key_id: str
    provider: str
    label: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    latency_ms: int
    success: bool
    error: str | None
    created_at: datetime


class LLMKeySummary(BaseModel):
    id: str
    name: str
    provider: str
    label: str
    status: LLMKeyStatus
    priority: int
    total_requests: int
    total_prompt_tokens: int
    total_completion_tokens: int
    estimated_cost_usd: float
    cooldown_until: datetime | None
    last_rotated_at: datetime | None


# ===== 代理调用 =====

class LLMChatRequest(BaseModel):
    provider: str
    model: str
    messages: list[dict[str, Any]]
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


# ===== 认证 =====

class LoginRequest(BaseModel):
    password: str


class TokenCreate(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=lambda: ["*"])
    expires_in_hours: int | None = None


class TokenOut(BaseModel):
    id: str
    name: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked: bool


class TokenCreated(TokenOut):
    """创建时返回明文 token，仅此一次。"""
    token: str


# ===== 通用 =====

class MessageOut(BaseModel):
    message: str
    detail: Any | None = None


class RotationReminder(BaseModel):
    credential_id: str
    name: str
    type: CredentialType
    expires_at: datetime | None
    last_rotated_at: datetime | None
    days_until_expire: int | None
    days_since_rotation: int | None
