"""用量记录与查询。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import desc, func, select, update

from ..db import session_scope
from ..models import LLMKey, UsageLog
from ..schemas import LLMKeySummary, UsageOut


def record_usage(
    llm_key_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cost_usd: float,
    latency_ms: int,
    success: bool,
    error: str | None,
) -> None:
    total = prompt_tokens + completion_tokens
    now = datetime.utcnow()
    with session_scope() as s:
        s.add(UsageLog(
            llm_key_id=llm_key_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            success=success,
            error=error,
            created_at=now,
        ))
        # 原子增量更新：用 SQL 表达式避免并发 read-modify-write 丢失更新。
        # SQLite 单写者模型保证单条 UPDATE 串行执行，但「读出→+=→写回」
        # 在两个并发事务中会各自读到旧值导致计数偏低。
        s.execute(
            update(LLMKey)
            .where(LLMKey.id == llm_key_id)
            .values(
                total_requests=LLMKey.total_requests + 1,
                total_prompt_tokens=LLMKey.total_prompt_tokens + prompt_tokens,
                total_completion_tokens=LLMKey.total_completion_tokens + completion_tokens,
                estimated_cost_usd=func.round(LLMKey.estimated_cost_usd + cost_usd, 6),
            )
        )


def list_usage(limit: int = 100, provider: str | None = None) -> list[UsageOut]:
    with session_scope() as s:
        stmt = (
            select(UsageLog, LLMKey.provider, LLMKey.label)
            .join(LLMKey, UsageLog.llm_key_id == LLMKey.id)
            .order_by(desc(UsageLog.created_at))
            .limit(limit)
        )
        if provider:
            stmt = stmt.where(LLMKey.provider == provider)
        rows = s.execute(stmt).all()
        return [
            UsageOut(
                id=log.id,
                llm_key_id=log.llm_key_id,
                provider=prov,
                label=lbl,
                model=log.model,
                prompt_tokens=log.prompt_tokens,
                completion_tokens=log.completion_tokens,
                total_tokens=log.total_tokens,
                cost_usd=log.cost_usd,
                latency_ms=log.latency_ms,
                success=log.success,
                error=log.error,
                created_at=log.created_at,
            )
            for log, prov, lbl in rows
        ]


def list_llm_keys(provider: str | None = None) -> list[LLMKeySummary]:
    from ..models import Credential

    with session_scope() as s:
        stmt = select(LLMKey, Credential.name, Credential.last_rotated_at).join(
            Credential, LLMKey.credential_id == Credential.id
        )
        if provider:
            stmt = stmt.where(LLMKey.provider == provider)
        stmt = stmt.order_by(LLMKey.provider, LLMKey.priority.desc(), LLMKey.label)
        rows = s.execute(stmt).all()
        return [
            LLMKeySummary(
                id=k.id,
                name=name,
                provider=k.provider,
                label=k.label,
                status=k.status,
                priority=k.priority,
                weight=k.weight,
                monthly_budget_usd=k.monthly_budget_usd,
                avg_latency_ms=k.avg_latency_ms,
                total_requests=k.total_requests,
                total_prompt_tokens=k.total_prompt_tokens,
                total_completion_tokens=k.total_completion_tokens,
                estimated_cost_usd=k.estimated_cost_usd,
                cooldown_until=k.cooldown_until,
                last_rotated_at=last_rot,
            )
            for k, name, last_rot in rows
        ]


def aggregate_cost(provider: str | None = None) -> dict:
    with session_scope() as s:
        stmt = select(
            LLMKey.provider,
            func.sum(UsageLog.cost_usd).label("cost"),
            func.sum(UsageLog.total_tokens).label("tokens"),
            func.count(UsageLog.id).label("calls"),
        ).join(LLMKey, UsageLog.llm_key_id == LLMKey.id)
        if provider:
            stmt = stmt.where(LLMKey.provider == provider)
        stmt = stmt.group_by(LLMKey.provider)
        rows = s.execute(stmt).all()
        return {
            r.provider: {
                "cost_usd": round(r.cost or 0, 6),
                "total_tokens": int(r.tokens or 0),
                "calls": int(r.calls or 0),
            }
            for r in rows
        }
