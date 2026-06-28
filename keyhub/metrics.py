"""Prometheus 指标收集。

暴露 /metrics 端点，包含：
- LLM 代理请求数/延迟/成本/错误率
- 凭证操作计数
- 认证事件计数
- 缓存命中/未命中
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import APIRouter, Response

router = APIRouter(tags=["metrics"])

# LLM 代理指标
llm_requests_total = Counter(
    "keyhub_llm_requests_total",
    "Total LLM proxy requests",
    ["provider", "model", "status"],  # status: success/fail
)
llm_request_duration = Histogram(
    "keyhub_llm_request_duration_seconds",
    "LLM request duration in seconds",
    ["provider", "model"],
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120],
)
llm_cost_usd = Counter(
    "keyhub_llm_cost_usd_total",
    "Total LLM cost in USD",
    ["provider"],
)
llm_tokens_total = Counter(
    "keyhub_llm_tokens_total",
    "Total LLM tokens used",
    ["provider", "type"],  # type: prompt/completion
)
llm_cache_hits = Counter(
    "keyhub_llm_cache_hits_total",
    "LLM response cache hits",
)
llm_cache_misses = Counter(
    "keyhub_llm_cache_misses_total",
    "LLM response cache misses",
)

# 凭证指标
credential_operations = Counter(
    "keyhub_credential_operations_total",
    "Credential operations",
    ["action"],  # action: create/reveal/update/rotate/delete
)

# 认证指标
auth_events = Counter(
    "keyhub_auth_events_total",
    "Authentication events",
    ["event", "result"],  # event: unlock/lock/init; result: success/fail
)

# 系统指标
active_llm_keys = Gauge(
    "keyhub_active_llm_keys",
    "Number of active LLM keys",
)
vault_status = Gauge(
    "keyhub_vault_unlocked",
    "Vault unlock status (1=unlocked, 0=locked)",
)

@router.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
