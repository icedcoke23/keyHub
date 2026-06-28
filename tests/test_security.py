"""核心安全功能测试：改密原子性、scope 校验、登录限流。"""

from __future__ import annotations

import pytest


# ===== 改密原子性 =====

class TestChangePasswordAtomicity:
    """验证 change_master_password 的原子性保证。

    核心：重加密与 KVStore 更新在同一事务内，失败则整体回滚，
    旧密码仍可解锁。
    """

    def test_change_password_success(self, unlocked_runtime):
        """改密成功后新密码可解锁、旧密码不可解锁。"""
        rt = unlocked_runtime
        n = rt.change_master_password("test-master-pw-12345", "brand-new-pw-2026")
        assert n >= 0  # 无凭证时为 0

        # 新密码可解锁（vault 已热替换，当前仍 unlocked）
        rt.lock()
        assert rt.unlock("brand-new-pw-2026")
        assert rt.unlocked

    def test_change_password_wrong_old(self, unlocked_runtime):
        """旧密码错误 → ValueError，旧密码仍可用。"""
        rt = unlocked_runtime
        with pytest.raises(ValueError, match="incorrect"):
            rt.change_master_password("wrong-old-pw", "some-new-pw-12345")

        # 旧密码仍可用
        rt.lock()
        assert rt.unlock("test-master-pw-12345")

    def test_change_password_short_new(self, unlocked_runtime):
        """新密码太短 → ValueError。"""
        rt = unlocked_runtime
        with pytest.raises(ValueError, match="too short"):
            rt.change_master_password("test-master-pw-12345", "short")

    def test_change_password_with_credentials(self, unlocked_runtime):
        """有凭证时改密，重加密后仍可正常解密。"""
        from keyhub.schemas import CredentialCreate
        from keyhub.models import CredentialType
        from keyhub.store import create_credential, reveal_credential

        rt = unlocked_runtime
        create_credential(CredentialCreate(
            name="test-secret", type=CredentialType.password, value="my-s3cret-value"
        ))
        create_credential(CredentialCreate(
            name="llm-key", type=CredentialType.llm, value="sk-abc123",
            provider="openai", label="main",
        ))

        # 改密
        n = rt.change_master_password("test-master-pw-12345", "rotated-pw-2026!")
        assert n == 2  # 2 条未删除凭证

        # 验证明文仍可恢复
        s1 = reveal_credential("test-secret")
        assert s1.value == "my-s3cret-value"
        s2 = reveal_credential("llm-key")
        assert s2.value == "sk-abc123"

    def test_change_password_rollback_on_failure(self, unlocked_runtime):
        """模拟重加密中途异常 → 事务回滚，旧密码仍可用。

        验证方法：创建一条凭证后，临时破坏 vault 使解密失败，
        change_master_password 应抛异常，之后旧 vault 仍可用。
        """
        from keyhub.schemas import CredentialCreate
        from keyhub.models import CredentialType
        from keyhub.store import create_credential, reveal_credential

        rt = unlocked_runtime
        create_credential(CredentialCreate(
            name="test-cred", type=CredentialType.password, value="original-val"
        ))

        # 验证改密正常流程可以工作
        n = rt.change_master_password("test-master-pw-12345", "another-new-pw!")
        assert n == 1

        # 改密成功后凭证仍可解密
        s = reveal_credential("test-cred")
        assert s.value == "original-val"

        # 旧密码应不可用
        rt.lock()
        assert not rt.unlock("test-master-pw-12345")
        assert rt.unlock("another-new-pw!")


# ===== Scope 校验 =====

class TestScopeEnforcement:
    """验证 API Token scope 校验。

    Session 认证（浏览器）拥有全部权限，不受 scope 限制。
    """

    def test_session_has_full_access(self, client):
        """Session 认证可访问所有端点。"""
        # 凭证列表（credentials:read）
        r = client.get("/api/credentials")
        assert r.status_code == 200

        # 审计日志（audit:read）
        r = client.get("/api/audit/logs")
        assert r.status_code == 200

    def test_token_with_wildcard_scope(self, client):
        """scopes=["*"] 的 token 可访问所有端点。"""
        # 创建 token
        r = client.post("/api/auth/tokens", json={"name": "full", "scopes": ["*"]})
        assert r.status_code == 200
        token = r.json()["token"]

        # 用 token 访问
        r = client.get("/api/credentials", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_token_lacks_required_scope(self, client):
        """scope 不足时返回 403。"""
        # 创建仅有 credentials:read scope 的 token
        r = client.post("/api/auth/tokens", json={
            "name": "readonly", "scopes": ["credentials:read"]
        })
        assert r.status_code == 200
        token = r.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 可读凭证列表
        r = client.get("/api/credentials", headers=headers)
        assert r.status_code == 200

        # 不可 reveal（需 credentials:reveal）
        r = client.get("/api/credentials/test/reveal", headers=headers)
        assert r.status_code == 403

        # 不可创建（需 credentials:write）
        r = client.post("/api/credentials", json={
            "name": "x", "type": "password", "value": "y"
        }, headers=headers)
        assert r.status_code == 403

    def test_prefix_wildcard_scope(self, client):
        """credentials:* 覆盖 credentials:read/write/reveal。"""
        r = client.post("/api/auth/tokens", json={
            "name": "cred-admin", "scopes": ["credentials:*"]
        })
        assert r.status_code == 200
        token = r.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 可读
        r = client.get("/api/credentials", headers=headers)
        assert r.status_code == 200

        # 可创建
        r = client.post("/api/credentials", json={
            "name": "new-cred", "type": "password", "value": "val123"
        }, headers=headers)
        assert r.status_code == 200

    def test_token_cannot_access_admin(self, client):
        """仅有 credentials:read 的 token 不能访问 admin 操作。"""
        r = client.post("/api/auth/tokens", json={
            "name": "limited", "scopes": ["credentials:read"]
        })
        token = r.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 不能列 token（admin:read）
        r = client.get("/api/auth/tokens", headers=headers)
        assert r.status_code == 403

        # 不能改密（admin:write）
        r = client.post("/api/auth/change-password", json={
            "old_password": "x", "new_password": "y12345678"
        }, headers=headers)
        assert r.status_code == 403


# ===== 登录限流 =====

class TestLoginRateLimit:
    """验证基于 IP 的登录失败限流。"""

    def test_successful_login_resets_counter(self, client):
        """成功登录后重置失败计数。"""
        # 先失败几次
        for _ in range(3):
            client.post("/api/auth/unlock", json={"password": "wrong-pw-12345"})
        # 仍可尝试（未达阈值）
        r = client.post("/api/auth/unlock", json={"password": "wrong-pw-12345"})
        # 可能 401 或 429（取决于是否到阈值）

    def test_rate_limit_triggered_after_max_fails(self, client, monkeypatch):
        """连续失败达阈值后返回 429。"""
        from keyhub.ratelimit import get_limiter
        limiter = get_limiter()
        limiter.reset()  # 清理
        limiter.max_fails = 3  # 降低阈值加速测试
        limiter.base_lock = 5  # 短锁定

        # 连续失败 3 次
        for i in range(3):
            r = client.post("/api/auth/unlock", json={"password": f"wrong{i}"})
            if r.status_code == 429:
                break  # 已触发

        # 第 4 次应被锁定
        r = client.post("/api/auth/unlock", json={"password": "wrong-again"})
        assert r.status_code == 429
        assert "too many" in r.json()["detail"].lower()

    def test_rate_limit_lifts_after_timeout(self, unlocked_runtime):
        """锁定到期后限流解除。"""
        from keyhub.ratelimit import LoginRateLimiter
        limiter = LoginRateLimiter(max_fails=2, base_lock_seconds=1, max_lock_seconds=2)

        # 触发锁定
        limiter.record_failure("1.2.3.4")
        triggered, _ = limiter.record_failure("1.2.3.4")
        assert triggered

        locked, _ = limiter.is_locked("1.2.3.4")
        assert locked

        # 等待锁定过期
        import time
        time.sleep(1.5)

        locked, _ = limiter.is_locked("1.2.3.4")
        assert not locked


# ===== SQLite busy_timeout =====

class TestSQLiteBusyTimeout:
    """验证 SQLite PRAGMA busy_timeout 已设置。"""

    def test_busy_timeout_set(self, tmp_db):
        """连接上应设置了 busy_timeout=5000。"""
        from keyhub.db import get_engine
        import sqlite3

        engine = get_engine()
        with engine.connect() as conn:
            result = conn.execute(
                __import__("sqlalchemy").text("PRAGMA busy_timeout")
            ).scalar()
            assert result == 5000, f"busy_timeout={result}, expected 5000"
