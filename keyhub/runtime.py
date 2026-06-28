"""运行时单例：持有 CryptoVault、初始化状态、当前会话信息。

进程启动后：
1. init_db() 建表
2. 若未初始化 → 等待 `keyhub init` 设置主密码
3. 若已初始化 → unlock(password) 派生主密钥，构造 CryptoVault
4. 服务对外可用
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select

from .config import get_settings
from .crypto import (
    Argon2Params,
    CryptoVault,
    derive_master_key,
    hash_master_password,
    new_argon2_params,
    verify_master_password,
)
from .db import session_scope
from .models import KVStore


# KVStore 中的键名
_KV_ARGON2_PARAMS = "argon2_params"
_KV_MASTER_PW_HASH = "master_pw_hash"
_KV_INITIALIZED = "initialized"


@dataclass
class InitStatus:
    initialized: bool
    locked: bool  # True = 已初始化但未解锁（主密钥未派生）


class Runtime:
    _instance: Optional["Runtime"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "Runtime":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._vault = None  # type: ignore[attr-defined]
                cls._instance._initialized = None  # type: ignore[attr-defined]
        return cls._instance

    # ===== 初始化状态 =====

    def is_initialized(self) -> bool:
        if self._initialized is None:
            with session_scope() as s:
                row = s.execute(
                    select(KVStore).where(KVStore.key == _KV_INITIALIZED)
                ).scalar_one_or_none()
                self._initialized = row is not None and row.value == "1"
        return self._initialized

    def status(self) -> InitStatus:
        return InitStatus(
            initialized=self.is_initialized(),
            locked=self._vault is None,
        )

    # ===== 首次初始化 =====

    def initialize(self, master_password: str) -> None:
        if self.is_initialized():
            raise RuntimeError("KeyHub already initialized")
        settings = get_settings()
        params = new_argon2_params(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
        )
        master_key = derive_master_key(master_password, params)
        pw_hash = hash_master_password(master_password)
        try:
            with session_scope() as s:
                s.add(KVStore(key=_KV_ARGON2_PARAMS, value=json.dumps(params.to_dict())))
                s.add(KVStore(key=_KV_MASTER_PW_HASH, value=pw_hash))
                s.add(KVStore(key=_KV_INITIALIZED, value="1"))
            self._vault = CryptoVault(params, master_key)
            self._initialized = True
        except Exception:
            # 清零派生密钥
            bytearray(master_key)[:0]  # no-op, kept for clarity
            raise

    # ===== 解锁 =====

    def unlock(self, master_password: str) -> bool:
        if not self.is_initialized():
            raise RuntimeError("KeyHub not initialized; run `keyhub init` first")
        with session_scope() as s:
            params_row = s.execute(
                select(KVStore).where(KVStore.key == _KV_ARGON2_PARAMS)
            ).scalar_one()
            hash_row = s.execute(
                select(KVStore).where(KVStore.key == _KV_MASTER_PW_HASH)
            ).scalar_one()
        if not verify_master_password(master_password, hash_row.value):
            return False
        params = Argon2Params.from_dict(json.loads(params_row.value))
        master_key = derive_master_key(master_password, params)
        self._vault = CryptoVault(params, master_key)
        return True

    # ===== 锁定 / 退出 =====

    def lock(self) -> None:
        if self._vault is not None:
            self._vault.zero()
            self._vault = None

    @property
    def vault(self) -> CryptoVault:
        if self._vault is None:
            raise RuntimeError("KeyHub is locked; unlock with master password first")
        return self._vault

    @property
    def unlocked(self) -> bool:
        return self._vault is not None


def get_runtime() -> Runtime:
    return Runtime()
