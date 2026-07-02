"""模型别名映射管理。

支持：
- 纯模型名别名（同 provider 内）
- "provider/model" 格式的跨 provider 别名
"""

from __future__ import annotations

import json
import threading
from typing import Optional

from sqlalchemy import select

from ..db import session_scope
from ..models import KVStore

_KV_KEY = "model_aliases"

PRESETS: dict[str, tuple[str, str]] = {
    "gpt-4": ("openai", "gpt-4-turbo"),
    "claude": ("anthropic", "claude-3-sonnet-20240229"),
}


class ModelAliasManager:
    _instance: Optional["ModelAliasManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "ModelAliasManager":
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._aliases: dict[str, tuple[str, str]] = {}
                inst._loaded = False
                cls._instance = inst
            return cls._instance

    def _load(self) -> None:
        if self._loaded:
            return
        with session_scope() as s:
            row = s.execute(
                select(KVStore).where(KVStore.key == _KV_KEY)
            ).scalar_one_or_none()
            if row is not None:
                try:
                    data = json.loads(row.value)
                    self._aliases = {k: tuple(v) for k, v in data.items()}
                except Exception:
                    self._aliases = {}
            else:
                self._aliases = {}
        self._loaded = True

    def _save(self) -> None:
        with session_scope() as s:
            row = s.execute(
                select(KVStore).where(KVStore.key == _KV_KEY)
            ).scalar_one_or_none()
            data = {k: list(v) for k, v in self._aliases.items()}
            value = json.dumps(data)
            if row is None:
                s.add(KVStore(key=_KV_KEY, value=value))
            else:
                row.value = value

    def resolve(self, provider: str, model: str) -> tuple[str, str]:
        self._load()
        if "/" in model:
            parts = model.split("/", 1)
            possible_alias_provider = parts[0]
            possible_alias_model = parts[1]
            if possible_alias_model in self._aliases:
                return self._aliases[possible_alias_model]
            return possible_alias_provider, possible_alias_model
        if model in self._aliases:
            return self._aliases[model]
        return provider, model

    def add_alias(self, alias: str, provider: str, model: str) -> None:
        self._load()
        self._aliases[alias] = (provider, model)
        self._save()

    def remove_alias(self, alias: str) -> bool:
        self._load()
        if alias in self._aliases:
            del self._aliases[alias]
            self._save()
            return True
        return False

    def list_aliases(self) -> dict[str, tuple[str, str]]:
        self._load()
        return dict(self._aliases)


def get_alias_manager() -> ModelAliasManager:
    return ModelAliasManager()
