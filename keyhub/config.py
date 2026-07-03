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
    # 可信代理数量：仅当请求经过恰好 N 层可信反代时才信任 X-Forwarded-For。
    # 0 = 完全不信任 XFF，始终用 request.client.host（适用于直连或未知反代）。
    # 1 = 信任 1 层反代（取 XFF 倒数第 1 个 IP，即真实客户端）。
    # 部署在 Nginx/CDN 后建议设为对应层数。
    trusted_proxy_depth: int = 0
    # 可信反代 IP 白名单（逗号分隔）。仅当 request.client.host 在白名单内时
    # 才解析 XFF，防止直连/未知反代下伪造 XFF 绕过 IP 限流。
    # 为空时仅按 trusted_proxy_depth 判断（向后兼容）。
    trusted_proxy_ips: str = ""
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
        """确保 secret_key 可用。

        优先级：
        1. 环境变量 KEYHUB_SECRET_KEY（推荐，多 worker 部署必用）
        2. 持久化文件 <db_path 同级目录>/secret_key（自动生成，跨 worker 共享）
           使用跨进程文件锁（fcntl.flock）确保多 worker 启动时串行化：
           第一个 worker 生成并写入文件，后续 worker 读取同一文件。
        3. 内存随机生成（仅当文件不可写时的兜底，单 worker 场景）

        多 worker 部署下若密钥不一致，session cookie 跨 worker 不兼容，
        表现为：解锁成功但 API 401 → "会话已过期"。
        """
        if self.secret_key:
            return self.secret_key

        import logging
        log = logging.getLogger("keyhub")

        key_file = Path(self.db_path).resolve().parent / "secret_key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        lock_file = key_file.with_suffix(".lock")

        def _load_or_create() -> str:
            # 文件已存在 → 读取
            try:
                if key_file.exists():
                    saved = key_file.read_text(encoding="utf-8").strip()
                    if saved:
                        self.secret_key = saved
                        log.info("KEYHUB_SECRET_KEY 从持久化文件加载: %s", key_file)
                        return self.secret_key
            except OSError as e:
                log.warning("读取 secret_key 文件失败 (%s): %s", key_file, e)
            # 生成新密钥并原子写入
            self.secret_key = _secrets.token_urlsafe(48)
            try:
                tmp = key_file.with_suffix(".tmp")
                tmp.write_text(self.secret_key, encoding="utf-8")
                tmp.replace(key_file)
                try:
                    key_file.chmod(0o600)
                except OSError:
                    pass  # Windows 不支持 chmod
                log.warning(
                    "KEYHUB_SECRET_KEY 未设置，已随机生成并持久化到 %s。"
                    "多 worker 将共享此密钥。生产环境建议通过环境变量显式配置。",
                    key_file,
                )
            except OSError as e:
                log.warning(
                    "无法持久化 secret_key 到文件 (%s): %s。"
                    "多 worker 部署将导致 session 不兼容，请设置 KEYHUB_SECRET_KEY 环境变量。",
                    key_file, e,
                )
            return self.secret_key

        # 跨进程文件锁，确保多 worker 串行化（Linux/Mac 用 fcntl）
        try:
            import fcntl
            with open(lock_file, "w") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                return _load_or_create()
        except (ImportError, OSError):
            # Windows 无 fcntl 或锁文件不可用，直接操作（单 worker 无影响）
            return _load_or_create()


@lru_cache
def get_settings() -> Settings:
    return Settings()
