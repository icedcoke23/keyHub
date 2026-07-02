"""Prometheus 指标暴露。

定义 KeyHub 自定义指标，并通过 /metrics 端点暴露（prometheus_client 默认格式）。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST,
    )
    _HAS_PROM = True
except ImportError:
    _HAS_PROM = False

router = APIRouter(tags=["metrics"])

if _HAS_PROM:
    # LLM 请求总数（按 provider/model/status 标签）
    llm_requests_total = Counter(
        "keyhub_llm_requests_total",
        "Total LLM proxy requests",
        ["provider", "model", "status"],
    )
    # LLM 请求延迟（秒）
    llm_request_duration = Histogram(
        "keyhub_llm_request_duration_seconds",
        "LLM request duration in seconds",
        ["provider", "model"],
        buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0),
    )
    # LLM 累计成本（美元）
    llm_cost_total = Counter(
        "keyhub_llm_cost_usd_total",
        "Total LLM cost in USD",
        ["provider", "model"],
    )
    # LLM token 使用量
    llm_tokens_total = Counter(
        "keyhub_llm_tokens_total",
        "Total LLM tokens used",
        ["provider", "model", "kind"],
    )
    # 缓存命中/未命中
    llm_cache_hits = Counter(
        "keyhub_llm_cache_hits_total",
        "LLM response cache hits",
    )
    llm_cache_misses = Counter(
        "keyhub_llm_cache_misses_total",
        "LLM response cache misses",
    )
    # 凭证数
    credentials_total = Gauge(
        "keyhub_credentials_total",
        "Total credentials count",
    )
    # 活跃 LLM key 数
    llm_keys_active = Gauge(
        "keyhub_llm_keys_active",
        "Active LLM keys count",
    )
    # 审计日志数
    audit_logs_total = Gauge(
        "keyhub_audit_logs_total",
        "Total audit log entries",
    )
    # token 限流次数
    token_rate_limited_total = Counter(
        "keyhub_token_rate_limited_total",
        "Token rate limited count",
    )


@router.get("/metrics")
def metrics():
    """Prometheus 指标端点。"""
    if not _HAS_PROM:
        return Response(content="# prometheus_client not installed\n", media_type="text/plain")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
