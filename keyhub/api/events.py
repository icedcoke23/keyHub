"""SSE 实时事件推送端点。

提供：
- GET /api/events/audit  审计日志实时流（SSE）
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from ..auth import require_scope

router = APIRouter(prefix="/api/events", tags=["events"])

# SSE 并发订阅者上限：防止通过大量长连接耗尽内存/文件描述符（DoS）。
# 每个 subscriber 持有一个 maxsize=100 的 asyncio.Queue，50 个上限约
# 占用可接受内存，同时满足正常多标签页/多用户场景。
MAX_SSE_SUBSCRIBERS = 50


class EventBroadcaster:
    """内存级事件广播器（单例）。

    使用 asyncio.Queue 进行订阅者管理。支持多订阅者并发接收事件。
    注意：由于 record() 在同步线程中调用，broadcast() 使用线程安全方式入队。
    """
    _instance: EventBroadcaster | None = None
    _lock = threading.Lock()

    def __new__(cls) -> EventBroadcaster:
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._subscribers: set[asyncio.Queue] = set()
                inst._sub_lock = threading.Lock()
                cls._instance = inst
            return cls._instance

    def subscriber_count(self) -> int:
        with self._sub_lock:
            return len(self._subscribers)

    def subscribe(self) -> asyncio.Queue | None:
        """订阅事件，返回接收队列。达到上限时返回 None（调用方应回 503）。"""
        with self._sub_lock:
            if len(self._subscribers) >= MAX_SSE_SUBSCRIBERS:
                return None
            q: asyncio.Queue = asyncio.Queue(maxsize=100)
            self._subscribers.add(q)
            return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """取消订阅。"""
        with self._sub_lock:
            self._subscribers.discard(q)

    def broadcast(self, event: dict[str, Any]) -> None:
        """广播事件给所有订阅者（线程安全，可在任意线程调用）。"""
        data = json.dumps(event, ensure_ascii=False)
        msg = f"data: {data}\n\n"
        with self._sub_lock:
            dead_qs = []
            for q in self._subscribers:
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    dead_qs.append(q)
                except Exception:
                    dead_qs.append(q)
            for q in dead_qs:
                self._subscribers.discard(q)


def get_broadcaster() -> EventBroadcaster:
    return EventBroadcaster()


async def _audit_event_generator(actor: str):
    """SSE 事件生成器（async generator）。"""
    bc = get_broadcaster()
    q = bc.subscribe()
    if q is None:
        # 订阅者已满：生成器立即结束，StreamingResponse 会发送已 yield 的内容
        yield "event: error\ndata: {\"error\": \"too many SSE subscribers\"}\n\n"
        return
    try:
        yield "event: connected\ndata: {}\n\n"
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15.0)
                yield msg
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
            except asyncio.CancelledError:
                break
    finally:
        bc.unsubscribe(q)


@router.get("/audit")
async def audit_events(actor: str = Depends(require_scope("audit:read"))):
    """审计日志实时 SSE 流。

    前端通过 EventSource 订阅，收到 data 为 JSON 格式的审计日志条目。
    每 15 秒发送一次 keepalive 注释防止连接超时。

    并发订阅者上限 MAX_SSE_SUBSCRIBERS，超过时返回 503。
    """
    bc = get_broadcaster()
    if bc.subscriber_count() >= MAX_SSE_SUBSCRIBERS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="too many concurrent SSE subscribers, try again later",
            headers={"Retry-After": "30"},
        )
    return StreamingResponse(
        _audit_event_generator(actor),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
