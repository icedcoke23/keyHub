"""pytest 共享 fixture。

每个测试用例使用独立的临时数据库，避免相互干扰。
Runtime 单例需在测试间重置。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    """使用临时数据库路径，并重置全局 engine/session/runtime 单例。"""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("KEYHUB_DB_PATH", str(db_path))
    monkeypatch.setenv("KEYHUB_SECRET_KEY", "test-secret-key-fixed")

    # 重置 db 单例
    from keyhub import db as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    # 重置 runtime 单例
    from keyhub import runtime as rt_mod
    rt_mod.Runtime._instance = None

    # 重置 config 单例（lru_cache，确保读取新 env）
    from keyhub import config as cfg_mod
    cfg_mod.get_settings.cache_clear()

    # 重置 balancer / notifier / ratelimiter 单例
    from keyhub.llm import balancer as bal_mod
    bal_mod._balancer = None
    from keyhub import ratelimit as rl_mod
    rl_mod._limiter = None

    db_mod.init_db()
    yield db_path

    # 清理
    db_mod._engine = None
    db_mod._SessionLocal = None
    rt_mod.Runtime._instance = None


@pytest.fixture
def unlocked_runtime(tmp_db):
    """已初始化并解锁的 runtime，返回 runtime 实例。"""
    from keyhub.runtime import get_runtime
    rt = get_runtime()
    rt.initialize("test-master-pw-12345")
    assert rt.unlocked
    return rt


@pytest.fixture
def client(tmp_db):
    """已初始化并解锁的 FastAPI TestClient（带 session cookie）。"""
    from keyhub.runtime import get_runtime
    rt = get_runtime()
    rt.initialize("test-master-pw-12345")

    from fastapi.testclient import TestClient
    from keyhub.main import app
    with TestClient(app) as c:
        # 解锁建立 session cookie
        r = c.post("/api/auth/unlock", json={"password": "test-master-pw-12345"})
        assert r.status_code == 200, r.text
        yield c
