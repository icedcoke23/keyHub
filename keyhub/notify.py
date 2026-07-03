"""通知模块：Webhook + 邮件 + 控制台。

所有通知器实现统一接口 notify(event, payload)。
- Webhook：POST JSON 到配置 URL，可选 HMAC-SHA256 签名头
- Email：SMTP 发送（阻塞，超时 10s），强制 STARTTLS 防止明文中继
- Console：打印到 stdout（兜底）

通知失败仅打印告警，不抛异常（通知不应阻塞业务）。
日志输出对敏感字段做脱敏处理，避免 secret/token/凭证明文落盘。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
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

# 日志脱敏：匹配这些键名（大小写不敏感、子串匹配）的字段值会被替换为 ***。
# 目的：避免将 secret/token/password/api_key/凭证明文打印到 stdout 或落盘日志。
_REDACT_KEY_FRAGMENTS = (
    "secret", "password", "passwd", "token", "api_key", "apikey",
    "key_value", "credential_value", "value", "private_key",
    "access_key", "secret_key", "bearer", "authorization",
)
_MAX_REDACT_DEPTH = 8


def _redact(obj: Any, _depth: int = 0) -> Any:
    """递归脱敏：将 dict 中键名含敏感片段的值替换为 '***'。

    深度限制 _MAX_REDACT_DEPTH 防止恶意嵌套导致栈溢出。
    """
    if _depth > _MAX_REDACT_DEPTH:
        return "***"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(frag in kl for frag in _REDACT_KEY_FRAGMENTS):
                out[k] = "***"
            else:
                out[k] = _redact(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [_redact(x, _depth + 1) for x in obj]
    return obj


def _build_smtp_ssl_context() -> ssl.SSLContext:
    """构建严格的 SSL 上下文用于 SMTP STARTTLS / SMTPS。

    - 仅允许 TLS 1.2+，禁用 SSLv2/SSLv3/TLSv1/TLSv1.1
    - 默认开启证书验证（hostname + CA）
    内部自签 SMTP 服务需放宽时，可通过系统 CA 配置或显式信任解决，
    而非在此处全局关闭验证。
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


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

        所有渠道（日志/webhook/邮件）统一使用脱敏后的 payload，
        避免 secret/token/凭证明文落盘日志或经中继传输。
        """
        # dedup 基于原始 payload（仅用 key_id/name/credential_id，不含敏感值）
        if self._is_duplicate(event, payload):
            print(f"[notify] {event}: deduplicated (suppressed duplicate within {_DEDUP_WINDOW_SECONDS}s)", flush=True)
            return

        # 先脱敏再格式化：确保 _formatted.message（由 payload 派生）也不含敏感字段。
        # 此前先格式化再脱敏，_formatted.message 是 JSON 字符串，_redact 无法识别其中的敏感键。
        safe = _redact(payload)
        formatted = self._format_event(event, safe)
        full_payload = {
            **safe,
            "_formatted": formatted,
            "_event": event,
        }

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
            # 邮件正文同样脱敏，避免 SMTP 中继/收件箱留存明文凭证
            safe = _redact(payload)
            text = json.dumps(safe, ensure_ascii=False, indent=2, default=str)
            msg = MIMEText(text, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = settings.notify_email_from
            msg["To"] = settings.notify_email_to
            msg["Date"] = formatdate(localtime=True)

            port = settings.notify_email_smtp_port
            require_tls = settings.notify_email_require_tls

            # 465 = SMTPS 隐式 TLS；其它端口走 STARTTLS 协商
            if port == 465:
                ctx = _build_smtp_ssl_context()
                with smtplib.SMTP_SSL(settings.notify_email_smtp_host, port,
                                      timeout=10, context=ctx) as smtp:
                    smtp.ehlo()
                    if settings.notify_email_smtp_user:
                        smtp.login(settings.notify_email_smtp_user,
                                   settings.notify_email_smtp_password)
                    self._smtp_send(smtp, settings, msg)
                return

            with smtplib.SMTP(settings.notify_email_smtp_host, port, timeout=10) as smtp:
                smtp.ehlo()
                did_tls = False
                # require_tls=True：必须成功协商 STARTTLS，否则中止投递，
                # 防止在明文通道中继 SMTP 凭证 / 邮件正文
                if require_tls:
                    smtp.starttls(context=_build_smtp_ssl_context())
                    smtp.ehlo()
                    did_tls = True
                elif port != 25:
                    # 兼容旧行为：非 25 端口尝试 STARTTLS，失败不致命
                    try:
                        smtp.starttls(context=_build_smtp_ssl_context())
                        smtp.ehlo()
                        did_tls = True
                    except smtplib.SMTPException:
                        pass
                if require_tls and not did_tls:
                    # 理论上 starttls() 失败会抛异常，此处兜底
                    raise RuntimeError("STARTTLS required but not negotiated")
                if settings.notify_email_smtp_user:
                    smtp.login(settings.notify_email_smtp_user,
                               settings.notify_email_smtp_password)
                self._smtp_send(smtp, settings, msg)
        except Exception as e:  # noqa: BLE001
            print(f"[notify] email failed: {e}", flush=True)

    @staticmethod
    def _smtp_send(smtp, settings, msg) -> None:
        recipients = [a.strip() for a in settings.notify_email_to.split(",") if a.strip()]
        smtp.sendmail(settings.notify_email_from, recipients, msg.as_string())


_notifier: Notifier | None = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
