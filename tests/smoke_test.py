"""端到端冒烟测试：加密、存储、负载均衡逻辑（不实际请求上游）。"""

from __future__ import annotations

import os
import sys

# 使用临时数据库
os.environ["KEYHUB_DB_PATH"] = "/tmp/keyhub_test.db"
os.environ["KEYHUB_SECRET_KEY"] = "test-secret-key-for-smoke-test-only"

# 清理旧库
try:
    os.remove("/tmp/keyhub_test.db")
except OSError:
    pass

from keyhub.config import get_settings
from keyhub.db import init_db, session_scope
from keyhub.runtime import get_runtime
from keyhub.crypto import CryptoVault, new_argon2_params, derive_master_key
from keyhub.schemas import CredentialCreate
from keyhub.store import create_credential, reveal_credential, list_credentials, rotate_credential
from keyhub.models import CredentialType
from keyhub.llm.balancer import get_balancer, NoAvailableKeyError
from keyhub.llm.tracker import list_llm_keys, aggregate_cost
from keyhub.llm.providers import estimate_cost


def main():
    # 1. 加解密单元
    params = new_argon2_params(time_cost=1, memory_cost=8192, parallelism=1)
    mk = derive_master_key("smoke-password", params)
    vault = CryptoVault(params, mk)
    blob = vault.encrypt("sk-secret-12345")
    assert vault.decrypt(blob) == "sk-secret-12345"
    print("[1/6] AES-256-GCM 加解密 OK")

    # 2. 初始化运行时
    init_db()
    rt = get_runtime()
    rt.initialize("smoke-master-pw")
    assert rt.unlocked
    assert rt.is_initialized()
    print("[2/6] 运行时初始化 + 解锁 OK")

    # 3. 凭证 CRUD
    c1 = create_credential(CredentialCreate(
        name="openai-main", type=CredentialType.llm, value="sk-aaa",
        provider="openai", label="main", rotation_days=90,
    ))
    c2 = create_credential(CredentialCreate(
        name="openai-backup", type=CredentialType.llm, value="sk-bbb",
        provider="openai", label="backup",
    ))
    c3 = create_credential(CredentialCreate(
        name="db-password", type=CredentialType.password, value="p@ssw0rd",
    ))
    assert len(list_credentials()) == 3
    secret = reveal_credential("openai-main")
    assert secret.value == "sk-aaa"
    print("[3/6] 凭证 CRUD + 解密 OK")

    # 4. 轮换
    rotated = rotate_credential("openai-main", "sk-aaa-new")
    assert reveal_credential("openai-main").value == "sk-aaa-new"
    assert rotated.last_rotated_at is not None
    print("[4/6] 凭证轮换 + 历史记录 OK")

    # 5. 负载均衡：两个 openai key 应轮询
    balancer = get_balancer()
    picks = [balancer.pick("openai", "gpt-4o").label for _ in range(4)]
    # 至少出现过两个不同的 label
    assert len(set(picks)) == 2, f"轮询异常: {picks}"
    # 不存在的 provider 应抛错
    try:
        balancer.pick("nonexistent", None)
        assert False, "应抛 NoAvailableKeyError"
    except NoAvailableKeyError:
        pass
    # 模型白名单过滤
    print(f"[5/6] 负载均衡轮询 OK: {picks}")

    # 6. 用量记录 + 成本估算
    from keyhub.llm.tracker import record_usage
    keys = list_llm_keys(provider="openai")
    record_usage(keys[0].id, "gpt-4o", 1000, 500,
                 estimate_cost("openai", "gpt-4o", 1000, 500), 800, True, None)
    record_usage(keys[0].id, "gpt-4o", 2000, 1000,
                 estimate_cost("openai", "gpt-4o", 2000, 1000), 1200, True, None)
    keys_after = list_llm_keys(provider="openai")
    assert keys_after[0].total_requests == 2
    assert keys_after[0].total_prompt_tokens == 3000
    cost = aggregate_cost(provider="openai")
    assert cost["openai"]["calls"] == 2
    assert cost["openai"]["cost_usd"] > 0
    print(f"[6/6] 用量记录 + 成本估算 OK: {cost}")

    # 清理
    rt.lock()
    print("\n所有冒烟测试通过 ✅")


if __name__ == "__main__":
    main()
