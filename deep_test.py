"""KeyHub 本地深度端到端测试。

覆盖：
- 认证与凭证 CRUD 全链路
- LLM 代理增强（缓存/路由/预算/指标/延迟）
- 密码管理增强（生成器/TOTP/健康检查/导入）
- 安全增强（自动锁定/速率限制/审计保留）
- 可观测性（Prometheus 指标/结构化日志/延迟分位数）
- OpenAI 兼容 API
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import httpx

BASE = "http://127.0.0.1:8765"
MASTER_PW = "deep-test-master-2026!"

# 全局共享 Cookie/Token
SESSION_COOKIE: str | None = None
API_TOKEN: str | None = None

PASS = 0
FAIL = 0
ERRORS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        msg = f"  [FAIL] {name}" + (f" — {detail}" if detail else "")
        print(msg)
        ERRORS.append(msg)


def req(method: str, path: str, **kwargs) -> httpx.Response:
    """带 session cookie 的请求。"""
    if SESSION_COOKIE:
        kwargs.setdefault("headers", {})
        kwargs["headers"]["Cookie"] = f"keyhub_session={SESSION_COOKIE}"
    with httpx.Client(timeout=30) as c:
        return c.request(method, f"{BASE}{path}", **kwargs)


def req_token(method: str, path: str, **kwargs) -> httpx.Response:
    """带 API Token 的请求。"""
    kwargs.setdefault("headers", {})
    kwargs["headers"]["Authorization"] = f"Bearer {API_TOKEN}"
    with httpx.Client(timeout=30) as c:
        return c.request(method, f"{BASE}{path}", **kwargs)


def jget(r: httpx.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return {}


# ===== 1. 认证与凭证 CRUD =====

def test_auth_and_credential_crud():
    print("\n========== 1. 认证与凭证 CRUD 全链路 ==========")

    # 1.1 初始化
    r = req("POST", "/api/auth/init", json={"password": MASTER_PW})
    check("初始化主密码", r.status_code == 200, f"status={r.status_code}")

    # 1.2 重复初始化应失败
    r = req("POST", "/api/auth/init", json={"password": "another"})
    check("重复初始化被拒绝", r.status_code == 400)

    # 1.3 错误密码解锁
    r = req("POST", "/api/auth/unlock", json={"password": "wrong-pw"})
    check("错误密码解锁失败", r.status_code == 401)

    # 1.4 正确解锁并保存 cookie
    global SESSION_COOKIE
    r = req("POST", "/api/auth/unlock", json={"password": MASTER_PW})
    check("正确密码解锁", r.status_code == 200)
    cookies = r.headers.get("set-cookie", "")
    if "keyhub_session=" in cookies:
        SESSION_COOKIE = cookies.split("keyhub_session=")[1].split(";")[0]
    check("Session Cookie 已建立", SESSION_COOKIE is not None)

    # 1.5 状态查询
    r = req("GET", "/api/system/status")
    data = jget(r)
    check("解锁后状态正确", data.get("unlocked") is True, f"status={data}")

    # 1.6 创建带标签的 password 凭证
    r = req("POST", "/api/credentials", json={
        "name": "db-prod", "type": "password", "value": "P@ssw0rd!2026#Strong",
        "tags": ["prod", "critical", "db"],
        "rotation_days": 90,
    })
    check("创建带标签凭证", r.status_code == 200, f"status={r.status_code}")
    data = jget(r)
    check("标签已保存", data.get("tags") == ["prod", "critical", "db"], f"tags={data.get('tags')}")

    # 1.7 创建 LLM 凭证
    r = req("POST", "/api/credentials", json={
        "name": "openai-main", "type": "llm", "value": "sk-test-key-001",
        "provider": "openai", "label": "main",
        "tags": ["prod", "llm"],
    })
    check("创建 LLM 凭证", r.status_code == 200)

    r = req("POST", "/api/credentials", json={
        "name": "openai-backup", "type": "llm", "value": "sk-test-key-002",
        "provider": "openai", "label": "backup",
        "tags": ["backup", "llm"],
    })
    check("创建第二个 LLM 凭证", r.status_code == 200)

    # 1.8 重复名称
    r = req("POST", "/api/credentials", json={
        "name": "db-prod", "type": "password", "value": "dup",
    })
    check("重复名称被拒绝", r.status_code == 400)

    # 1.9 列表 + 搜索
    r = req("GET", "/api/credentials")
    all_creds = jget(r)
    check("凭证列表数量正确", len(all_creds) == 3, f"count={len(all_creds)}")

    r = req("GET", "/api/credentials?q=openai")
    searched = jget(r)
    check("搜索 openai 返回 2 条", len(searched) == 2, f"count={len(searched)}")

    r = req("GET", "/api/credentials?tag=prod")
    tagged = jget(r)
    check("tag=prod 过滤返回 2 条", len(tagged) == 2, f"count={len(tagged)}")

    r = req("GET", "/api/credentials?tag=backup")
    tagged = jget(r)
    check("tag=backup 过滤返回 1 条", len(tagged) == 1)

    # 1.10 reveal
    r = req("GET", "/api/credentials/db-prod/reveal")
    check("reveal 凭证", r.status_code == 200)
    check("reveal 值正确", jget(r).get("value") == "P@ssw0rd!2026#Strong")

    # 1.11 update
    r = req("PATCH", "/api/credentials/db-prod", json={
        "rotation_days": 60, "tags": ["prod", "updated"],
    })
    check("更新凭证", r.status_code == 200)
    check("rotation_days 已更新", jget(r).get("rotation_days") == 60)
    check("tags 已更新", jget(r).get("tags") == ["prod", "updated"])

    # 1.12 rotate
    r = req("POST", "/api/credentials/db-prod/rotate?new_value=RotatedPass!2026")
    check("轮换凭证", r.status_code == 200)
    r = req("GET", "/api/credentials/db-prod/reveal")
    check("轮换后值正确", jget(r).get("value") == "RotatedPass!2026")

    # 1.13 API Token 创建
    r = req("POST", "/api/auth/tokens", json={
        "name": "deep-test-token", "scopes": ["*"],
    })
    check("创建 API Token", r.status_code == 200)
    global API_TOKEN
    API_TOKEN = jget(r).get("token")
    check("Token 已返回", API_TOKEN is not None)

    # 1.14 用 Token 访问
    r = req_token("GET", "/api/credentials")
    check("Token 访问凭证列表", r.status_code == 200)


# ===== 2. LLM 代理增强 =====

def test_llm_proxy_enhancements():
    print("\n========== 2. LLM 代理增强 ==========")

    # 2.1 /v1/models
    r = req("GET", "/v1/models")
    data = jget(r)
    check("/v1/models 返回列表", data.get("object") == "list")
    models = data.get("data", [])
    check("/v1/models 含 openai 模型", any(m.get("owned_by") == "openai" for m in models),
          f"models={[m.get('id') for m in models]}")

    # 2.2 供应商推断
    from keyhub.api.v1 import infer_provider
    check("infer gpt-4o-mini", infer_provider("gpt-4o-mini") == "openai")
    check("infer claude-3-opus", infer_provider("claude-3-opus") == "anthropic")
    check("infer deepseek-chat", infer_provider("deepseek-chat") == "deepseek")
    check("infer qwen-max", infer_provider("qwen-max") == "qwen")
    check("infer glm-4", infer_provider("glm-4") == "glm")
    check("infer moonshot-v1", infer_provider("moonshot-v1") == "moonshot")
    check("infer unknown 默认 openai", infer_provider("unknown-model") == "openai")

    # 2.3 /v1/chat/completions 无可用网络（应返回友好错误）
    r = req("POST", "/v1/chat/completions", json={
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
    })
    check("chat completions 返回错误格式", r.status_code in (502, 500))
    err = jget(r).get("error", {})
    check("错误响应 OpenAI 格式", "message" in err and "type" in err, f"err={err}")

    # 2.4 缓存统计
    r1 = req("GET", "/api/llm/cache/stats")
    stats_before = jget(r1)
    check("缓存统计端点可用", r1.status_code == 200, f"stats={stats_before}")

    # 2.5 缓存清空
    r = req("POST", "/api/llm/cache/clear")
    check("清空缓存", r.status_code == 200)

    # 2.6 成本趋势
    r = req("GET", "/api/llm/cost/trend")
    check("成本趋势端点", r.status_code == 200)

    # 2.7 延迟统计
    r = req("GET", "/api/llm/latency")
    check("延迟统计端点", r.status_code == 200)

    # 2.8 负载均衡策略切换
    # 注意：2.3 的失败调用可能已将 openai key 标记为 error/冷却，
    # 此处先重置 key 状态以确保策略测试有可用 key
    from keyhub.config import get_settings
    from keyhub.db import session_scope as _ss
    from keyhub.models import LLMKey, LLMKeyStatus
    from sqlalchemy import update as _upd
    with _ss() as s:
        s.execute(_upd(LLMKey).where(LLMKey.provider == "openai").values(
            status=LLMKeyStatus.active, cooldown_until=None
        ))
    settings = get_settings()
    original_strategy = settings.llm_balance_strategy
    for strategy in ["round_robin", "latency", "cost", "weighted"]:
        settings.llm_balance_strategy = strategy
        from keyhub.llm.balancer import get_balancer
        bal = get_balancer()
        picks = []
        for _ in range(4):
            try:
                k = bal.pick("openai", "gpt-4o")
                picks.append(k.label)
            except Exception:
                break
        check(f"策略 {strategy} 可选 key", len(picks) > 0, f"picks={picks}")
    settings.llm_balance_strategy = original_strategy

    # 2.9 balancer mark_ok 延迟跟踪（EMA）
    from keyhub.llm.balancer import get_balancer
    from keyhub.db import session_scope
    from keyhub.models import LLMKey
    from sqlalchemy import select
    bal = get_balancer()
    with session_scope() as s:
        keys = s.execute(select(LLMKey).where(LLMKey.provider == "openai")).scalars().all()
        if keys:
            bal.mark_ok(keys[0].id, 500)
            bal.mark_ok(keys[0].id, 700)
            s.commit()
            # expire_on_commit=False，需手动 expire 以读到 mark_ok 在另一 session 的更新
            s.expire_all()
            updated = s.get(LLMKey, keys[0].id)
            check("avg_latency_ms EMA 更新", updated.avg_latency_ms > 0,
                  f"latency={updated.avg_latency_ms}")


# ===== 3. 密码管理增强 =====

def test_password_management():
    print("\n========== 3. 密码管理增强 ==========")

    # 3.1 密码生成器 API
    r = req("GET", "/api/credentials/utils/generate-password?length=32&symbols=true")
    check("密码生成器 API", r.status_code == 200)
    data = jget(r)
    pw = data.get("password", "")
    check("密码长度 32", len(pw) == 32, f"len={len(pw)}")
    check("强度评估返回", "strength" in data and "score" in data["strength"])

    # 3.2 不含符号
    r = req("GET", "/api/credentials/utils/generate-password?length=16&symbols=false")
    pw = jget(r).get("password", "")
    check("无符号密码生成", len(pw) == 16)

    # 3.3 排除相似字符
    r = req("GET", "/api/credentials/utils/generate-password?length=20&exclude_similar=true")
    pw = jget(r).get("password", "")
    similar = set("0O1lI|`")
    check("排除相似字符", not (set(pw) & similar), f"pw={pw}")

    # 3.4 crypto 模块单元测试
    from keyhub.crypto import (
        generate_password, password_strength,
        generate_totp_secret, generate_totp_uri, verify_totp,
        _hotp, _b32_decode,
    )
    import time as _time

    s = password_strength("123456")
    check("弱密码强度低", s["score"] <= 1, f"score={s['score']}")
    s = password_strength("Tr0ub4dour&3")
    check("中等密码强度中", 1 <= s["score"] <= 3, f"score={s['score']}")
    s = password_strength("C0rrect-Horse-Battery-Staple-2026!")
    check("强密码强度高", s["score"] >= 3, f"score={s['score']}, issues={s['issues']}")

    # TOTP 全流程
    secret = generate_totp_secret()
    check("TOTP 密钥 base32", len(secret) > 0)
    uri = generate_totp_uri(secret, "test@example.com", "TestIssuer")
    check("otpauth URI 格式", uri.startswith("otpauth://totp/"))
    check("URI 含 secret", "secret=" in uri)
    check("URI 含 issuer", "issuer=TestIssuer" in uri)

    counter = int(_time.time()) // 30
    code = _hotp(_b32_decode(secret), counter)
    check("TOTP 码 6 位数字", code.isdigit() and len(code) == 6, f"code={code}")
    check("TOTP 当前码验证", verify_totp(secret, code))
    check("TOTP 错误码拒绝", not verify_totp(secret, "000000"))
    old_code = _hotp(_b32_decode(secret), counter - 1)
    check("TOTP 上一窗口容错", verify_totp(secret, old_code, window=1))
    old2 = _hotp(_b32_decode(secret), counter - 2)
    check("TOTP 两步前拒绝 (window=1)", not verify_totp(secret, old2, window=1))

    # 3.5 健康检查 API
    r = req("GET", "/api/credentials/db-prod/health")
    check("健康检查端点", r.status_code == 200)
    data = jget(r)
    check("健康检查返回强度", "strength" in data)
    check("健康检查返回重复", "duplicates" in data and "has_duplicates" in data)

    # 3.6 创建重复值的凭证，验证重复检测
    req("POST", "/api/credentials", json={
        "name": "dup-cred", "type": "password", "value": "RotatedPass!2026",
    })
    r = req("GET", "/api/credentials/db-prod/health")
    data = jget(r)
    check("重复检测生效", data.get("has_duplicates") is True,
          f"duplicates={data.get('duplicates')}")

    # 3.7 批量导入
    r = req("POST", "/api/credentials/import", json=[
        {"name": "import-1", "type": "password", "value": "imp-pw-1", "tags": ["imported"]},
        {"name": "import-2", "type": "token", "value": "tok-abc"},
        {"name": "import-3", "type": "ssh_key", "value": "ssh-rsa-xxx"},
    ])
    check("批量导入", r.status_code == 200)
    data = jget(r)
    check("导入 3 条成功", data.get("imported") == 3, f"result={data}")

    # 3.8 重复名称导入应 skip
    r = req("POST", "/api/credentials/import", json=[
        {"name": "import-1", "type": "password", "value": "dup"},
    ])
    data = jget(r)
    check("重复名称 skip", data.get("skipped") == 1, f"result={data}")

    # 3.9 删除测试
    r = req("DELETE", "/api/credentials/dup-cred")
    check("删除凭证", r.status_code == 200)
    r = req("GET", "/api/credentials/dup-cred")
    check("删除后 404", r.status_code == 404)


# ===== 4. 安全增强 =====

def test_security_enhancements():
    print("\n========== 4. 安全增强 ==========")

    # 4.1 Token 速率限制
    from keyhub.ratelimit import get_token_limiter
    limiter = get_token_limiter()
    check("Token 限流器存在", limiter is not None)

    # 4.2 auto_lock 模块
    from keyhub.auto_lock import get_auto_lock_checker
    al = get_auto_lock_checker()
    check("AutoLock 单例存在", al is not None)
    before = al._last_activity
    time.sleep(0.01)
    al.touch()
    check("AutoLock touch 更新时间", al._last_activity >= before)

    # 4.3 审计日志清理
    from keyhub.audit import cleanup_old_logs
    n = cleanup_old_logs(0)
    check("retention=0 不清理", n == 0)

    # 4.4 审计日志查询
    r = req("GET", "/api/audit/logs")
    check("审计日志端点", r.status_code == 200)
    logs = jget(r)
    check("审计日志非空", isinstance(logs, list) and len(logs) > 0,
          f"count={len(logs) if isinstance(logs, list) else 'N/A'}")

    # 4.5 审计日志按动作过滤
    r = req("GET", "/api/audit/logs?action=auth.unlock")
    logs = jget(r)
    if isinstance(logs, list):
        all_unlock = all(l.get("action") == "auth.unlock" for l in logs)
        check("审计日志过滤正确", all_unlock, f"count={len(logs)}")

    # 4.6 scope 校验
    r = req("POST", "/api/auth/tokens", json={
        "name": "readonly", "scopes": ["credentials:read"],
    })
    limited_token = jget(r).get("token")
    r = req("GET", "/api/credentials", headers={"Authorization": f"Bearer {limited_token}"})
    check("受限 token 可读", r.status_code == 200)
    r = req("POST", "/api/credentials", json={"name": "x", "type": "password", "value": "y"},
            headers={"Authorization": f"Bearer {limited_token}"})
    check("受限 token 不可写 (403)", r.status_code == 403)
    r = req("GET", "/api/credentials/db-prod/reveal",
            headers={"Authorization": f"Bearer {limited_token}"})
    check("受限 token 不可 reveal (403)", r.status_code == 403)


# ===== 5. 可观测性 =====

def test_observability():
    print("\n========== 5. 可观测性 ==========")

    # 5.1 /metrics 端点
    r = req("GET", "/metrics")
    check("/metrics 端点可用", r.status_code == 200)
    text = r.text
    custom_metrics = [
        "keyhub_llm_requests_total",
        "keyhub_llm_request_duration_seconds",
        "keyhub_llm_cost_usd_total",
        "keyhub_llm_tokens_total",
        "keyhub_llm_cache_hits_total",
        "keyhub_llm_cache_misses_total",
    ]
    for m in custom_metrics:
        check(f"指标 {m} 存在", m in text)

    # 5.2 结构化日志模块
    from keyhub.structured_logging import setup_logging, get_logger
    setup_logging("INFO")
    logger = get_logger("test")
    check("结构化日志模块可加载", logger is not None)

    # 5.3 延迟分位数统计
    from keyhub.llm.latency_stats import get_latency_stats
    stats = get_latency_stats()
    check("LatencyStats 单例存在", stats is not None)

    for ms in [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]:
        stats.record("openai", ms)
    p50, p95, p99 = stats.percentiles("openai")
    check("P50 计算", p50 > 0, f"p50={p50}")
    check("P95 >= P50", p95 >= p50, f"p95={p95}, p50={p50}")
    check("P99 >= P95", p99 >= p95, f"p99={p99}, p95={p95}")

    # 5.4 指标计数增长验证
    r_before = req("GET", "/metrics").text
    before_fail = 0.0
    for line in r_before.split("\n"):
        if line.startswith("keyhub_llm_requests_total") and "fail" in line:
            before_fail = float(line.split()[-1])
    req("POST", "/v1/chat/completions", json={
        "model": "gpt-4o-mini", "messages": [{"role": "user", "content": "test"}],
    })
    r_after = req("GET", "/metrics").text
    after_fail = 0.0
    for line in r_after.split("\n"):
        if line.startswith("keyhub_llm_requests_total") and "fail" in line:
            after_fail = float(line.split()[-1])
    check("指标计数增长", after_fail > before_fail,
          f"before={before_fail}, after={after_fail}")


# ===== 6. OpenAI 兼容 API 深度测试 =====

def test_openai_compatible_api():
    print("\n========== 6. OpenAI 兼容 API 深度测试 ==========")

    # 6.1 缺少 model
    r = req("POST", "/v1/chat/completions", json={"messages": []})
    check("缺少 model 返回 400", r.status_code == 400)
    err = jget(r).get("error", {})
    check("错误格式 OpenAI 风格", err.get("type") == "invalid_request_error")

    # 6.2 keyhub_provider 显式指定
    r = req("POST", "/v1/chat/completions", json={
        "model": "custom-model", "keyhub_provider": "anthropic",
        "messages": [{"role": "user", "content": "hi"}],
    })
    check("keyhub_provider 覆盖推断", r.status_code in (502, 500))

    # 6.3 /v1/embeddings
    r = req("POST", "/v1/embeddings", json={
        "model": "text-embedding-3-small", "input": "hello",
    })
    check("/v1/embeddings 端点响应", r.status_code in (502, 500))

    # 6.4 流式 chat
    r = req("POST", "/v1/chat/completions", json={
        "model": "gpt-4o-mini", "stream": True,
        "messages": [{"role": "user", "content": "hi"}],
    })
    check("流式端点响应", r.status_code == 200)
    check("流式 content-type", "text/event-stream" in r.headers.get("content-type", ""))


# ===== 7. 边界与错误处理 =====

def test_edge_cases():
    print("\n========== 7. 边界与错误处理 ==========")

    # 7.1 不存在的凭证
    r = req("GET", "/api/credentials/nonexistent")
    check("不存在的凭证 404", r.status_code == 404)

    # 7.2 未认证访问
    with httpx.Client(timeout=10) as c:
        r = c.get(f"{BASE}/api/credentials")
    check("未认证 401", r.status_code == 401)

    # 7.3 无效 token
    with httpx.Client(timeout=10) as c:
        r = c.get(f"{BASE}/api/credentials", headers={"Authorization": "Bearer invalid-token-xxx"})
    check("无效 token 401", r.status_code == 401)

    # 7.4 锁定状态
    r = req("POST", "/api/auth/lock")
    check("锁定端点", r.status_code == 200)
    r = req("GET", "/api/credentials")
    check("锁定后访问 401", r.status_code == 401)
    r = req("POST", "/api/auth/unlock", json={"password": MASTER_PW})
    check("重新解锁", r.status_code == 200)
    global SESSION_COOKIE
    cookies = r.headers.get("set-cookie", "")
    if "keyhub_session=" in cookies:
        SESSION_COOKIE = cookies.split("keyhub_session=")[1].split(";")[0]

    # 7.5 密码生成器参数边界
    r = req("GET", "/api/credentials/utils/generate-password?length=3")
    check("长度过短 422", r.status_code == 422)
    r = req("GET", "/api/credentials/utils/generate-password?length=200")
    check("长度过长 422", r.status_code == 422)

    # 7.6 导入空数组
    r = req("POST", "/api/credentials/import", json=[])
    data = jget(r)
    check("导入空数组", data.get("imported") == 0 and data.get("errors") == [])


def main():
    print("=" * 60)
    print("KeyHub 本地深度端到端测试")
    print(f"目标: {BASE}")
    print("=" * 60)

    try:
        test_auth_and_credential_crud()
        test_llm_proxy_enhancements()
        test_password_management()
        test_security_enhancements()
        test_observability()
        test_openai_compatible_api()
        test_edge_cases()
    except Exception as e:
        import traceback
        print(f"\n!!! 测试中断: {e}")
        traceback.print_exc()
        global FAIL
        FAIL += 1

    print("\n" + "=" * 60)
    print(f"测试结果: PASS={PASS}, FAIL={FAIL}")
    print("=" * 60)
    if ERRORS:
        print("\n失败项:")
        for e in ERRORS:
            print(e)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
