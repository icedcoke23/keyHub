"""通知模块：Webhook + 邮件 + 控制台。

所有通知器实现统一接口 notify(event, payload)。
- Webhook：POST JSON 到配置 URL，可选 HMAC-SHA256 签名头
- Email：SMTP 发送（阻塞，超时 10s）
- Console：打印到 stdout（兜底）

通知失败仅打印告警，不抛异常（通知不应阻塞业务）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Any

import httpx

from .config import get_settings


_EVENT_FORMATTERS = {
    "llm.key_test_result": lambda p: {
        "title": "LLM Key 测试结果",
        "message": f"Key {p.get('key_id', 'unknown')} 测试{'成功' if p.get('success') else '失败'}"
                   + (f": {p.get('error', '')}" if not p.get('success') else ""),
        "level": "info" if p.get("success") else "warning",
    },
    "llm.circuit_breaker": lambda p: {
        "title": "熔断器触发",
        "message": f"Key {p.get('key_id', 'unknown')} ({p.get('provider', 'unknown')}/{p.get('label', '')}) "
                   f"熔断器已触发，冷却至 {p.get('cooldown_until', 'unknown')}",
        "level": "warning",
    },
    "credential.rollback": lambda p: {
        "title": "凭证回滚通知",
        "message": f"凭证 {p.get('name', 'unknown')} 已回滚到上一版本"
                   + (f"，原因：{p.get('reason', '')}" if p.get("reason") else ""),
        "level": "warning",
    },
}

_DEDUP_WINDOW_SECONDS = 300
_MAX_RETRIES = 2
_RETRY_INTERVAL_SECONDS = 1


class Notifier:
    """通知器聚合：按配置启用 Webhook / 邮件，始终启用控制台。"""

    def __init__(self):
        self._dedup_cache: dict[str, float] = {}
        self._dedup_lock = threading.Lock()

    def _is_duplicate(self, event: str, payload: dict[str, Any]) -> bool:
        key = self._dedup_key(event, payload)
        now = time.time()
        with self._dedup_lock:
            self._cleanup_dedup(now)
            if key in self._dedup_cache:
                return True
            self._dedup_cache[key] = now
            return False

    def _dedup_key(self, event: str, payload: dict[str, Any]) -> str:
        key_id = payload.get("key_id") or payload.get("name") or payload.get("credential_id") or ""
        return f"{event}:{key_id}"

    def _cleanup_dedup(self, now: float) -> None:
        expired = [
            k for k, ts in self._dedup_cache.items()
            if now - ts > _DEDUP_WINDOW_SECONDS
        ]
        for k in expired:
            del self._dedup_cache[k]

    def _format_event(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        formatter = _EVENT_FORMATTERS.get(event)
        if formatter:
            try:
                return formatter(payload)
            except Exception:
                pass
        return {
            "title": event,
            "message": json.dumps(payload, ensure_ascii=False, default=str),
            "level": "info",
        }

    def notify(self, event: str, payload: dict[str, Any]) -> None:
        """同步发送通知到所有已配置的渠道。

        为避免阻塞调用方，建议在后台线程调用。event 是事件类型
        （如 'rotation.reminder'），payload 是任意可序列化数据。
        """
        formatted = self._format_event(event, payload)
        full_payload = {
            **payload,
            "_formatted": formatted,
            "_event": event,
        }

        if self._is_duplicate(event, payload):
            print(f"[notify] {event}: deduplicated (suppressed duplicate within {_DEDUP_WINDOW_SECONDS}s)", flush=True)
            return

        print(f"[notify] {event}: {json.dumps(full_payload, ensure_ascii=False, default=str)}",
              flush=True)

        settings = get_settings()

        if settings.notify_webhook_url:
            t = threading.Thread(
                target=self._send_webhook_with_retry,
                args=(settings, event, full_payload),
                daemon=True,
            )
            t.start()

        if settings.notify_email_enabled and settings.notify_email_smtp_host:
            t = threading.Thread(
                target=self._send_email,
                args=(settings, event, full_payload),
                daemon=True,
            )
            t.start()

    def _send_webhook_with_retry(self, settings, event: str, payload: dict) -> None:
        body = {"event": event, "payload": payload}
        data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if settings.notify_webhook_secret:
            sig = hmac.new(
                settings.notify_webhook_secret.encode("utf-8"),
                data,
                hashlib.sha256,
            ).hexdigest()
            headers["X-KeyHub-Signature"] = sig

        for attempt in range(_MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=10) as client:
                    r = client.post(settings.notify_webhook_url, content=data, headers=headers)
                if r.status_code < 400:
                    return
                print(f"[notify] webhook returned {r.status_code} (attempt {attempt + 1}/{_MAX_RETRIES + 1})", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"[notify] webhook failed (attempt {attempt + 1}/{_MAX_RETRIES + 1}): {e}", flush=True)

            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_INTERVAL_SECONDS)

    def _send_email(self, settings, event: str, payload: dict) -> None:
        try:
            formatted = payload.get("_formatted", {})
            subject = f"[KeyHub] {formatted.get('title', event)}"
            text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
            msg = MIMEText(text, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = settings.notify_email_from
            msg["To"] = settings.notify_email_to
            msg["Date"] = formatdate(localtime=True)

            with smtplib.SMTP(settings.notify_email_smtp_host,
                              settings.notify_email_smtp_port, timeout=10) as smtp:
                smtp.ehlo()
                if settings.notify_email_smtp_port != 25:
                    smtp.starttls()
                    smtp.ehlo()
                if settings.notify_email_smtp_user:
                    smtp.login(settings.notify_email_smtp_user,
                               settings.notify_email_smtp_password)
                recipients = [a.strip() for a in settings.notify_email_to.split(",") if a.strip()]
                smtp.sendmail(settings.notify_email_from, recipients, msg.as_string())
        except Exception as e:  # noqa: BLE001
            print(f"[notify] email failed: {e}", flush=True)


_notifier: Notifier | None = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
