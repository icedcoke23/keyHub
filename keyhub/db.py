"""数据库引擎与会话管理。"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


# SQLite 启用外键约束与 WAL
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover
    import sqlite3

    if isinstance(dbapi_conn, sqlite3.Connection):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.execute("PRAGMA synchronous=NORMAL;")
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
    """创建所有表。"""
    from .models import Base  # noqa: F401  ensure models imported

    Base.metadata.create_all(get_engine())
