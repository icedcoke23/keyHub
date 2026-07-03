"""结构化 JSON 日志。

配置 root logger 输出 JSON 格式日志，便于日志聚合系统采集。
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


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
        # 额外字段
        for key in ("provider", "model", "key_id", "status", "error"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        return json.dumps(log_entry, ensure_ascii=False, default=str)


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


# 这些异常类型由 KeyHub 自身显式抛出，其 message 是面向用户的受控文本
# （如 "name already exists"、"credential 'x' not found"），可直接回传客户端。
# 其它异常（如第三方库抛出的 DBError / SSL / 网络错误）可能携带内部状态、
# 文件路径、堆栈片段或上游响应体，必须经 safe_detail() 转为通用提示。
_SAFE_DETAIL_EXC_TYPES: tuple[type[BaseException], ...] = (ValueError, KeyError)


def safe_detail(exc: BaseException, fallback: str = "internal error") -> str:
    """返回对客户端安全的错误消息，同时把完整异常写入日志。

    - 受控异常（ValueError/KeyError）：直接返回 str(exc)，因其 message 由
      KeyHub 自身控制、面向用户。
    - 其它异常：记录 WARNING 级别日志（含类型名、消息与堆栈），向客户端
      仅返回 fallback，避免泄漏内部状态/路径/上游响应体。

    用法：
        except Exception as e:
            raise HTTPException(500, safe_detail(e, "backup failed"))
    """
    if isinstance(exc, _SAFE_DETAIL_EXC_TYPES):
        return str(exc)
    get_logger("keyhub").warning(
        "internal error (%s): %s",
        type(exc).__name__, exc, exc_info=True,
    )
    return fallback
