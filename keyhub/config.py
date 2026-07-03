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

    # LLM 代理超时（兼容字段，优先使用下面的精细超时）
    llm_timeout: int = 120
    # LLM 精细超时（秒）
    llm_connect_timeout: int = 10
    llm_read_timeout: int = 120
    # 响应缓存 TTL（秒），0 = 禁用
    llm_cache_ttl: int = 300
    # 负载均衡策略：round_robin / latency / cost / weighted / least_used
    llm_balance_strategy: str = "round_robin"
    # 跨 Provider 降级：同 provider 无可用 key 时，尝试其他 provider 同模型名 key
    llm_enable_cross_provider_fallback: bool = False

    # 空闲自动锁定（秒），0 = 禁用
    auto_lock_idle_seconds: int = 1800
    # API Token 速率限制（每分钟请求数，0 = 禁用）
    token_rpm_limit: int = 60
    # 每 Key RPM 限制（每分钟请求数，0 = 禁用）
    llm_key_rpm_limit: int = 0
    # 每 Key TPM 限制（每分钟 token 数，0 = 禁用）
    llm_key_tpm_limit: int = 0
    # LLM 最大并发请求数（0 = 不限）
    llm_max_concurrent: int = 0
    # 审计日志保留天数（0 = 禁用自动清理）
    audit_retention_days: int = 0

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
        """若未配置 secret_key，则启动时随机生成（重启后旧 token 失效）。

        多 worker 部署时务必设置 KEYHUB_SECRET_KEY 环境变量，
        否则各 worker 生成不同的密钥导致 session cookie 互不兼容，
        表现为页面能加载但 API 401（死循环）。
        """
        if not self.secret_key:
            self.secret_key = _secrets.token_urlsafe(48)
            import logging
            logging.getLogger("keyhub").warning(
                "KEYHUB_SECRET_KEY 未设置，已随机生成。"
                "多 worker 部署时会导致 session 不兼容，请通过环境变量配置固定密钥。"
            )
        return self.secret_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
