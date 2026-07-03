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

from ..auth import require_scope

router = APIRouter(prefix="/api/events", tags=["events"])

# 最大并发 SSE 订阅者，防止资源耗尽 DoS
MAX_SSE_SUBSCRIBERS = 50


class _Subscriber:
    """单个订阅者：持有队列与其所属事件循环。

    asyncio.Queue 非线程安全，跨线程入队必须经由所属 loop 的
    call_soon_threadsafe 调度，否则会与事件循环竞争内部状态。
    """

    __slots__ = ("queue", "loop")

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        self.queue = queue
        self.loop = loop


class EventBroadcaster:
    """内存级事件广播器（单例）。

    使用 asyncio.Queue 进行订阅者管理。支持多订阅者并发接收事件。
    broadcast() 可在任意线程（含同步审计记录线程）安全调用——通过
    loop.call_soon_threadsafe 把入队操作调度回订阅者的事件循环。
    """
    _instance: EventBroadcaster | None = None
    _lock = threading.Lock()

    def __new__(cls) -> EventBroadcaster:
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._subscribers: set[_Subscriber] = set()
                inst._sub_lock = threading.Lock()
                cls._instance = inst
            return cls._instance

    def subscribe(self) -> _Subscriber:
        """订阅事件，返回一个订阅者对象。超出上限抛 QueueFull。"""
        with self._sub_lock:
            if len(self._subscribers) >= MAX_SSE_SUBSCRIBERS:
                raise asyncio.QueueFull("too many SSE subscribers")
            sub = _Subscriber(asyncio.Queue(maxsize=100), asyncio.get_running_loop())
            self._subscribers.add(sub)
            return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        """取消订阅。"""
        with self._sub_lock:
            self._subscribers.discard(sub)

    def broadcast(self, event: dict[str, Any]) -> None:
        """广播事件给所有订阅者（线程安全，可在任意线程调用）。

        始终经由订阅者所属 loop 的 call_soon_threadsafe 调度入队，
        避免与事件循环竞争 asyncio.Queue 的内部状态。
        """
        data = json.dumps(event, ensure_ascii=False)
        msg = f"data: {data}\n\n"
        with self._sub_lock:
            subs = list(self._subscribers)
        dead: list[_Subscriber] = []
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(self._enqueue, sub, msg)
            except RuntimeError:
                # loop 已关闭，订阅者失效
                dead.append(sub)
        if dead:
            with self._sub_lock:
                for sub in dead:
                    self._subscribers.discard(sub)

    def _enqueue(self, sub: _Subscriber, msg: str) -> None:
        """在订阅者事件循环内执行入队；队列满则丢弃该订阅者。"""
        try:
            sub.queue.put_nowait(msg)
        except asyncio.QueueFull:
            with self._sub_lock:
                self._subscribers.discard(sub)
        except Exception:
            with self._sub_lock:
                self._subscribers.discard(sub)


def get_broadcaster() -> EventBroadcaster:
    return EventBroadcaster()


async def _audit_event_generator(actor: str):
    """SSE 事件生成器（async generator）。"""
    bc = get_broadcaster()
    try:
        sub = bc.subscribe()
    except asyncio.QueueFull:
        # 订阅者已满，仅推送一条提示后关闭
        yield "event: error\ndata: {\"message\":\"too many subscribers\"}\n\n"
        return
    try:
        yield "event: connected\ndata: {}\n\n"
        while True:
            try:
                msg = await asyncio.wait_for(sub.queue.get(), timeout=15.0)
                yield msg
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
            except asyncio.CancelledError:
                break
    finally:
        bc.unsubscribe(sub)


@router.get("/audit")
async def audit_events(actor: str = Depends(require_scope("audit:read"))):
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
