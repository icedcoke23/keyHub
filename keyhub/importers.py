"""凭证导入器：支持 Bitwarden JSON 和 KeePass CSV 格式。"""

from __future__ import annotations

import csv
import io
from typing import Any

from .models import CredentialType
from .schemas import CredentialCreate

# 导入条目数上限，防止恶意超大导出文件导致内存膨胀
MAX_IMPORT_ITEMS = 5000
# 单字段长度上限（截断，避免超长字段撑爆 DB / 日志）
MAX_FIELD_LENGTH = 4096


def _truncate(s: str, limit: int = MAX_FIELD_LENGTH) -> str:
    return s[:limit] if len(s) > limit else s


def import_bitwarden_json(data: list[dict[str, Any]]) -> list[CredentialCreate]:
    """解析 Bitwarden JSON 导出格式。

    Bitwarden 导出的 items 数组中，type=1 为登录项，包含 login.username/login.password。
    """
    results: list[CredentialCreate] = []
    for item in data:
        if len(results) >= MAX_IMPORT_ITEMS:
            break
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        if not name or not isinstance(name, str):
            continue
        name = _truncate(name.strip())

        login = item.get("login") or {}
        if not isinstance(login, dict):
            login = {}
        username = login.get("username") or ""
        password = login.get("password") or ""
        uris = login.get("uris") or []
        # 显式校验 uris 为 list，避免 dict 时 uris[0] 取键
        if isinstance(uris, list) and uris and isinstance(uris[0], dict):
            url = uris[0].get("uri") or ""
        else:
            url = ""
        notes = item.get("notes") or ""

        if not password or not isinstance(password, str):
            continue

        metadata: dict[str, Any] = {}
        if username and isinstance(username, str):
            metadata["username"] = _truncate(username)
        if url and isinstance(url, str):
            metadata["url"] = _truncate(url)
        if notes and isinstance(notes, str):
            metadata["notes"] = _truncate(notes)

        results.append(CredentialCreate(
            name=name,
            type=CredentialType.password,
            value=password,
            metadata=metadata,
        ))
    return results


def import_keepass_csv(data: str) -> list[CredentialCreate]:
    """解析 KeePass CSV 格式。

    字段映射：
    - Title    -> name
    - Password -> value
    - Username -> metadata.username
    - URL      -> metadata.url
    - Notes    -> metadata.notes
    """
    results: list[CredentialCreate] = []
    reader = csv.DictReader(io.StringIO(data))

    for row in reader:
        if len(results) >= MAX_IMPORT_ITEMS:
            break
        name = (row.get("Title") or "").strip()
        password = (row.get("Password") or "").strip()
        if not name or not password:
            continue

        username = (row.get("Username") or "").strip()
        url = (row.get("URL") or "").strip()
        notes = (row.get("Notes") or "").strip()

        metadata: dict[str, Any] = {}
        if username:
            metadata["username"] = _truncate(username)
        if url:
            metadata["url"] = _truncate(url)
        if notes:
            metadata["notes"] = _truncate(notes)

        tags = []
        tag_str = (row.get("Tags") or "").strip()
        if tag_str:
            tags = [t.strip() for t in tag_str.split(",") if t.strip()]

        results.append(CredentialCreate(
            name=_truncate(name),
            type=CredentialType.password,
            value=password,
            metadata=metadata,
            tags=tags,
        ))
    return results
