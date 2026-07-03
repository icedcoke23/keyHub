"""结构化 JSON 日志。

配置 root logger 输出 JSON 格式日志，便于日志聚合系统采集。
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

# 敏感字段名黑名单（大小写不敏感匹配）。命中则值脱敏为 ***，
# 防止主密码 / 明文 key / token 意外落盘。
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(password|passwd|secret|token|apikey|api_key|master|"
    r"credential|value|plaintext|cookie|authorization)(?:$|_)",
    re.IGNORECASE,
)


def _redact(obj):
    """递归脱敏：dict 的敏感 key → ***，字符串原样保留（由调用方负责不传明文）。"""
    if isinstance(obj, dict):
        return {
            k: ("***" if _SENSITIVE_KEY_RE.search(str(k)) else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_redact(x) for x in obj]
    return obj


class _SafeJSONEncoder(json.JSONEncoder):
    """JSON 编码器：未知类型回退为 repr（而非 str，避免触发 __str__ 泄漏敏感信息）。"""

    def default(self, o):
        try:
            return repr(o)
        except Exception:
            return "<unserializable>"


class JSONFormatter(logging.Formatter):
    """将日志记录格式化为 JSON 行。"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        # 额外字段（脱敏后写入）
        extra = {}
        for key in ("provider", "model", "key_id", "status", "error"):
            val = getattr(record, key, None)
            if val is not None:
                extra[key] = val
        if extra:
            log_entry["extra"] = _redact(extra)
        return json.dumps(log_entry, ensure_ascii=False, cls=_SafeJSONEncoder)


def setup_logging(level: str = "INFO") -> None:
    """配置全局 JSON 日志。"""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # 清除已有 handler
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
    # 降低第三方库噪音
    for noisy in ("uvicorn.access", "uvicorn.error", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
