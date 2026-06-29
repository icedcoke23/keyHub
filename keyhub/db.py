"""数据库引擎与会话管理。"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


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
        _engine = create_engine(
            settings.db_url,
            connect_args={"check_same_thread": False},
            future=True,
            # SQLite 单写者模型下，连接池不宜过大；pre_ping 探活避免 stale 连接
            pool_size=5,
            max_overflow=0,
            pool_pre_ping=True,
        )
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
    }

    with engine.begin() as conn:
        for table, cols in migrations.items():
            if not insp.has_table(table):
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for col_name, col_def in cols:
                if col_name not in existing:
                    conn.execute(
                        text(f'ALTER TABLE "{table}" ADD COLUMN "{col_name}" {col_def}')
                    )
