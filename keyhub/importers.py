"""凭证导入器：支持 Bitwarden JSON 和 KeePass CSV 格式。"""

from __future__ import annotations

import csv
import io
from typing import Any

from .models import CredentialType
from .schemas import CredentialCreate


def import_bitwarden_json(data: list[dict[str, Any]]) -> list[CredentialCreate]:
    """解析 Bitwarden JSON 导出格式。

    Bitwarden 导出的 items 数组中，type=1 为登录项，包含 login.username/login.password。
    """
    results: list[CredentialCreate] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        if not name:
            continue

        login = item.get("login") or {}
        username = login.get("username") or ""
        password = login.get("password") or ""
        uris = login.get("uris") or []
        url = uris[0].get("uri") if uris and isinstance(uris[0], dict) else ""
        notes = item.get("notes") or ""

        if not password:
            continue

        metadata: dict[str, Any] = {}
        if username:
            metadata["username"] = username
        if url:
            metadata["url"] = url
        if notes:
            metadata["notes"] = notes

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
        name = (row.get("Title") or "").strip()
        password = (row.get("Password") or "").strip()
        if not name or not password:
            continue

        username = (row.get("Username") or "").strip()
        url = (row.get("URL") or "").strip()
        notes = (row.get("Notes") or "").strip()

        metadata: dict[str, Any] = {}
        if username:
            metadata["username"] = username
        if url:
            metadata["url"] = url
        if notes:
            metadata["notes"] = notes

        tags = []
        tag_str = (row.get("Tags") or "").strip()
        if tag_str:
            tags = [t.strip() for t in tag_str.split(",") if t.strip()]

        results.append(CredentialCreate(
            name=name,
            type=CredentialType.password,
            value=password,
            metadata=metadata,
            tags=tags,
        ))
    return results
