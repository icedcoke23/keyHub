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

    # ===== 主密码变更 =====

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
        *,
        reencrypt: bool = True,
    ) -> int:
        """变更主密码。

        流程（全部在单一事务内完成，保证原子性）：
        1. 校验旧密码
        2. 用新密码派生新主密钥 + 新参数（新 salt）
        3. 单事务内：重新加密所有未删除凭证 + 更新 KVStore 参数/哈希
        4. 提交成功后才替换运行时 vault（替换前旧 vault 不动）

        返回重新加密的凭证数量。
        必须在已解锁状态下调用（保证旧 vault 可用）。

        原子性保证：步骤 3 在单事务内完成，若中途失败则整体回滚，
        凭证保持旧加密状态、KVStore 也未更新，仍可用旧密码解锁。
        只有事务提交成功后才会替换运行时 vault，避免「凭证已新加密但
        KVStore 未更新」导致的数据永久锁死。
        """
        if not self.is_initialized():
            raise RuntimeError("KeyHub not initialized")
        if not self.unlocked:
            raise RuntimeError("KeyHub must be unlocked before changing password")
        if len(new_password) < 8:
            raise ValueError("new password too short (min 8 chars)")

        # 1. 校验旧密码
        with session_scope() as s:
            hash_row = s.execute(
                select(KVStore).where(KVStore.key == _KV_MASTER_PW_HASH)
            ).scalar_one()
        if not verify_master_password(old_password, hash_row.value):
            raise ValueError("old master password incorrect")

        settings = get_settings()
        old_vault = self._vault

        # 2. 派生新主密钥（此时旧 vault 仍可用，新 vault 仅暂存）
        new_params = new_argon2_params(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost,
            parallelism=settings.argon2_parallelism,
        )
        new_master_key = derive_master_key(new_password, new_params)
        new_vault = CryptoVault(new_params, new_master_key)
        new_pw_hash = hash_master_password(new_password)

        # 3. 单事务：重新加密所有未删除凭证 + 更新 KVStore（原子提交）
        from .models import Credential  # 局部 import 避免循环
        reencrypted = 0
        try:
            with session_scope() as s:
                if reencrypt:
                    creds = s.execute(
                        select(Credential).where(Credential.deleted == False)  # noqa: E712
                    ).scalars().all()
                    for c in creds:
                        plaintext = old_vault.decrypt(c.encrypted_value)
                        c.encrypted_value = new_vault.encrypt(plaintext)
                        reencrypted += 1
                # 同一事务内更新 KVStore，保证与重加密原子提交
                params_row = s.execute(
                    select(KVStore).where(KVStore.key == _KV_ARGON2_PARAMS)
                ).scalar_one()
                params_row.value = json.dumps(new_params.to_dict())
                master_hash_row = s.execute(
                    select(KVStore).where(KVStore.key == _KV_MASTER_PW_HASH)
                ).scalar_one()
                master_hash_row.value = new_pw_hash
        except Exception:
            # 事务已回滚：凭证与 KVStore 均保持旧状态，旧 vault 仍可用
            # 清零新派生密钥
            new_vault.zero()
            raise

        # 4. 事务提交成功后才替换运行时 vault
        old_vault.zero()
        self._vault = new_vault
        return reencrypted

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
