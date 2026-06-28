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
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Any

import httpx

from .config import get_settings


class Notifier:
    """通知器聚合：按配置启用 Webhook / 邮件，始终启用控制台。"""

    def notify(self, event: str, payload: dict[str, Any]) -> None:
        """同步发送通知到所有已配置的渠道。

        为避免阻塞调用方，建议在后台线程调用。event 是事件类型
        （如 'rotation.reminder'），payload 是任意可序列化数据。
        """
        # 控制台（始终）
        print(f"[notify] {event}: {json.dumps(payload, ensure_ascii=False, default=str)}",
              flush=True)

        settings = get_settings()

        # Webhook
        if settings.notify_webhook_url:
            t = threading.Thread(
                target=self._send_webhook,
                args=(settings, event, payload),
                daemon=True,
            )
            t.start()

        # Email
        if settings.notify_email_enabled and settings.notify_email_smtp_host:
            t = threading.Thread(
                target=self._send_email,
                args=(settings, event, payload),
                daemon=True,
            )
            t.start()

    # ===== Webhook =====

    def _send_webhook(self, settings, event: str, payload: dict) -> None:
        try:
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
            with httpx.Client(timeout=10) as client:
                r = client.post(settings.notify_webhook_url, content=data, headers=headers)
            if r.status_code >= 400:
                print(f"[notify] webhook returned {r.status_code}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[notify] webhook failed: {e}", flush=True)

    # ===== Email =====

    def _send_email(self, settings, event: str, payload: dict) -> None:
        try:
            subject = f"[KeyHub] {event}"
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
