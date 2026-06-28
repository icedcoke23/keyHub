"""全局配置 —— 通过环境变量 / .env 加载。"""

from __future__ import annotations

import os
import secrets as _secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KEYHUB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # 运行环境
    env: str = "development"

    # 服务
    host: str = "127.0.0.1"
    port: int = 8000

    # 数据库
    db_path: str = "data/keyhub.db"

    # 主密码（运行时也可通过交互输入）
    master_password: str = ""

    # Argon2 派生参数（仅初始化时使用，后续不可更改）
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MiB
    argon2_parallelism: int = 4

    # Token / Session 签名密钥
    secret_key: str = ""

    # API Token 有效期（小时）
    token_expire_hours: int = 720

    # LLM 代理超时
    llm_timeout: int = 120

    # 后台轮换检查间隔（秒）
    rotation_check_interval: int = 3600
    rotation_warn_days: int = 7

    # Web UI
    web_ui: bool = True

    # 通知
    notify_webhook_url: str = ""           # 通用 Webhook（POST JSON）
    notify_webhook_secret: str = ""        # Webhook 签名密钥（X-KeyHub-Signature = hmac-sha256）
    notify_email_enabled: bool = False
    notify_email_smtp_host: str = ""
    notify_email_smtp_port: int = 587
    notify_email_smtp_user: str = ""
    notify_email_smtp_password: str = ""
    notify_email_from: str = ""
    notify_email_to: str = ""              # 逗号分隔多个收件人

    @property
    def db_url(self) -> str:
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path.resolve()}"

    @property
    def is_prod(self) -> bool:
        return self.env.lower() == "production"

    def ensure_secret_key(self) -> str:
        """若未配置 secret_key，则启动时随机生成（重启后旧 token 失效）。"""
        if not self.secret_key:
            self.secret_key = _secrets.token_urlsafe(48)
        return self.secret_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
