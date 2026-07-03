"""数据库引擎与会话管理。"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

# 合法 SQL 标识符白名单（字母/下划线开头，仅含字母数字下划线）
# 用于 _auto_migrate 的 ALTER TABLE 语句，防御性校验即便当前来源是硬编码
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# SQLite 启用外键约束、WAL 与 busy_timeout
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover
    import sqlite3

    if isinstance(dbapi_conn, sqlite3.Connection):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        # busy_timeout：并发写入时等待最多 5s 而非立即报 SQLITE_BUSY，
        # 避免 rotation-checker / notifier / 请求线程并发写时 "database is locked"
        cur.execute("PRAGMA busy_timeout=5000;")
        cur.close()


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        kwargs: dict = {
            "future": True,
            "pool_pre_ping": True,
        }
        # SQLite 单写者模型：多连接不提升写并发，反而增加 SQLITE_BUSY 概率。
        # 用 NullPool 让每个 session 独占连接（配合 busy_timeout 串行化），
        # 避免连接池在多 worker 下跨进程共享文件型 DB 的写锁竞争。
        if settings.db_url.startswith("sqlite"):
            from sqlalchemy.pool import NullPool
            kwargs["poolclass"] = NullPool
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            # Postgres 等服务端 DB 用默认 QueuePool
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 0
        _engine = create_engine(settings.db_url, **kwargs)
    return _engine


def get_sessionmaker() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            class_=Session,
        )
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    """事务作用域：自动提交/回滚/关闭。"""
    sm = get_sessionmaker()
    s = sm()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def init_db() -> None:
    """创建所有表，并对已有表执行轻量级自动迁移（ALTER TABLE ADD COLUMN）。"""
    from .models import Base  # noqa: F401  ensure models imported

    Base.metadata.create_all(get_engine())
    _auto_migrate()


def _auto_migrate() -> None:
    """检查并补充新增列，确保旧数据库平滑升级。"""
    from sqlalchemy import inspect, text

    engine = get_engine()
    insp = inspect(engine)

    migrations: dict[str, list[tuple[str, str]]] = {
        "credentials": [
            ("tags", "JSON"),
        ],
        "llm_keys": [
            ("weight", "INTEGER DEFAULT 1"),
            ("monthly_budget_usd", "FLOAT DEFAULT 0.0"),
            ("avg_latency_ms", "INTEGER DEFAULT 0"),
        ],
        "rotation_log": [
            ("encrypted_value", "BLOB"),
        ],
    }

    with engine.begin() as conn:
        for table, cols in migrations.items():
            if not insp.has_table(table):
                continue
            # 防御性校验表名（当前硬编码，但防止未来从配置读入引入注入）
            if not _IDENT_RE.match(table):
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for col_name, col_def in cols:
                if col_name not in existing:
                    if not _IDENT_RE.match(col_name):
                        continue
                    # col_def 当前为硬编码类型定义（如 "INTEGER DEFAULT 1"），
                    # 此处不拼接用户输入，但仍校验 col_name 防御未来扩展
                    conn.execute(
                        text(f'ALTER TABLE "{table}" ADD COLUMN "{col_name}" {col_def}')
                    )
