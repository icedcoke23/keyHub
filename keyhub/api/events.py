"""SSE 实时事件推送端点。

提供：
- GET /api/events/audit  审计日志实时流（SSE）
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import require_auth

router = APIRouter(prefix="/api/events", tags=["events"])


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

    def subscribe(self) -> asyncio.Queue:
        """订阅事件，返回一个接收队列。"""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        with self._sub_lock:
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
async def audit_events(actor: str = Depends(require_auth)):
    """审计日志实时 SSE 流。

    前端通过 EventSource 订阅，收到 data 为 JSON 格式的审计日志条目。
    每 15 秒发送一次 keepalive 注释防止连接超时。
    """
    return StreamingResponse(
        _audit_event_generator(actor),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
