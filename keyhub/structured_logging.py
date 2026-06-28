"""结构化 JSON 日志。

使用标准 logging 模块 + JSON formatter，
输出包含 timestamp/level/module/message 的结构化日志。
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """JSON 格式化器，输出结构化日志行。"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        # 附加自定义字段
        for key, value in record.__dict__.items():
            if key not in ("args", "msg", "levelname", "module", "exc_info",
                          "exc_text", "stack_info", "filename", "funcName",
                          "lineno", "levelno", "pathname", "processName",
                          "process", "thread", "threadName", "relativeCreated",
                          "msecs", "name", "created"):
                if key.startswith("_"):
                    log_entry[key[1:]] = value
        return json.dumps(log_entry, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO") -> None:
    """配置结构化 JSON 日志。"""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    # 降低 uvicorn 等库的日志级别
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
