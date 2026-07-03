"""凭证 CRUD 路由。"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from ..models import AuditAction, CredentialType
from ..schemas import (
    CredentialCreate,
    CredentialOut,
    CredentialSecret,
    CredentialUpdate,
    MessageOut,
    RotateRequest,
    RotationLogOut,
)
from ..store import (
    create_credential,
    delete_credential,
    get_credential,
    get_credential_history,
    list_credentials,
    reveal_credential,
    rollback_credential,
    rotate_credential,
    update_credential,
)
from ..auth import require_auth, require_scope
from ..audit import record as audit_record
from ..importers import import_bitwarden_json, import_keepass_csv

router = APIRouter(prefix="/api/credentials", tags=["credentials"])

logger = logging.getLogger(__name__)

# 单次导入数量上限，防止 DoS 与误操作
MAX_IMPORT_ITEMS = 5000


@router.post("", response_model=CredentialOut)
def create(body: CredentialCreate, actor: str = Depends(require_scope("credentials:write"))):
    try:
        return create_credential(body, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("", response_model=list[CredentialOut])
def list_all(
    type: CredentialType | None = Query(None),
    q: str | None = Query(None, description="搜索凭证名"),
    tag: str | None = Query(None, description="按标签过滤"),
    _: str = Depends(require_scope("credentials:read")),
):
    return list_credentials(type_filter=type, q=q, tag=tag)


@router.get("/utils/generate-password")
def generate_password(
    length: int = Query(20, ge=4, le=128),
    upper: bool = Query(True),
    lower: bool = Query(True),
    digits: bool = Query(True),
    symbols: bool = Query(True),
    exclude_similar: bool = Query(True),
    _: str = Depends(require_scope("credentials:read")),
):
    from ..crypto import generate_password as gen_pw, password_strength
    pw = gen_pw(length=length, upper=upper, lower=lower, digits=digits,
                symbols=symbols, exclude_similar=exclude_similar)
    return {"password": pw, "strength": password_strength(pw)}


@router.post("/import")
def import_credentials(
    body: dict[str, Any] | list[dict],
    format: str = Query("json", description="导入格式: json, bitwarden, keepass_csv"),
    actor: str = Depends(require_scope("credentials:write")),
):
    results = {"imported": 0, "skipped": 0, "errors": []}

    if format == "json":
        if not isinstance(body, list):
            raise HTTPException(400, "json format expects a list of credential items")
        items = body
        if len(items) > MAX_IMPORT_ITEMS:
            raise HTTPException(413, f"too many items: {len(items)} (max {MAX_IMPORT_ITEMS})")
    elif format == "bitwarden":
        if isinstance(body, dict) and "items" in body:
            items_data = body["items"]
        elif isinstance(body, list):
            items_data = body
        else:
            raise HTTPException(400, "bitwarden format expects a list of items or {items: [...]}")
        try:
            creds_to_import = import_bitwarden_json(items_data)
        except Exception as e:
            raise HTTPException(400, f"failed to parse bitwarden data: {e}")
        if len(creds_to_import) > MAX_IMPORT_ITEMS:
            raise HTTPException(413, f"too many items: {len(creds_to_import)} (max {MAX_IMPORT_ITEMS})")
        for data in creds_to_import:
            try:
                create_credential(data, actor=actor)
                results["imported"] += 1
            except ValueError as e:
                if "already exists" in str(e):
                    results["skipped"] += 1
                else:
                    results["errors"].append({"name": data.name, "error": str(e)})
            except Exception as e:
                logger.exception("import bitwarden item %r failed", data.name)
                results["errors"].append({"name": data.name, "error": "internal error"})
        audit_record(AuditAction.credential_import, actor, detail={**results, "format": format})
        return results
    elif format == "keepass_csv":
        if not isinstance(body, dict) or "csv" not in body:
            raise HTTPException(400, 'keepass_csv format expects {"csv": "..."} body')
        csv_data = body["csv"]
        try:
            creds_to_import = import_keepass_csv(csv_data)
        except Exception as e:
            raise HTTPException(400, f"failed to parse CSV data: {e}")
        if len(creds_to_import) > MAX_IMPORT_ITEMS:
            raise HTTPException(413, f"too many items: {len(creds_to_import)} (max {MAX_IMPORT_ITEMS})")
        for data in creds_to_import:
            try:
                create_credential(data, actor=actor)
                results["imported"] += 1
            except ValueError as e:
                if "already exists" in str(e):
                    results["skipped"] += 1
                else:
                    results["errors"].append({"name": data.name, "error": str(e)})
            except Exception as e:
                logger.exception("import keepass item %r failed", data.name)
                results["errors"].append({"name": data.name, "error": "internal error"})
        audit_record(AuditAction.credential_import, actor, detail={**results, "format": format})
        return results
    else:
        raise HTTPException(400, f"unsupported format: {format}")

    for item in items:
        try:
            data = CredentialCreate(**item)
            create_credential(data, actor=actor)
            results["imported"] += 1
        except ValueError as e:
            if "already exists" in str(e):
                results["skipped"] += 1
            else:
                results["errors"].append({"name": item.get("name", "?"), "error": str(e)})
        except Exception as e:
            logger.exception("import json item %r failed", item.get("name", "?"))
            results["errors"].append({"name": item.get("name", "?"), "error": "internal error"})
    audit_record(AuditAction.credential_import, actor, detail={**results, "format": format})
    return results


@router.get("/export")
def export_credentials(
    format: str = Query("json", description="导出格式: json, csv"),
    actor: str = Depends(require_scope("credentials:reveal")),
):
    all_creds = list_credentials()
    secrets = []
    for c in all_creds:
        try:
            secret = reveal_credential(c.name, actor=actor)
            secrets.append(secret)
        except Exception:
            continue

    if format == "json":
        result = []
        for s in secrets:
            result.append({
                "name": s.name,
                "type": s.type.value,
                "value": s.value,
                "metadata": s.metadata,
                "tags": s.tags,
            })
        audit_record(AuditAction.backup_export, actor, detail={"format": "json", "count": len(result)})
        return result
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["name", "type", "value", "username", "url", "tags", "notes"])
        for s in secrets:
            username = s.metadata.get("username", "") if s.metadata else ""
            url = s.metadata.get("url", "") if s.metadata else ""
            notes = s.metadata.get("notes", "") if s.metadata else ""
            tags_str = ",".join(s.tags) if s.tags else ""
            writer.writerow([s.name, s.type.value, s.value, username, url, tags_str, notes])
        csv_content = output.getvalue()
        audit_record(AuditAction.backup_export, actor, detail={"format": "csv", "count": len(secrets)})
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=keyhub-export.csv"},
        )
    else:
        raise HTTPException(400, f"unsupported format: {format}")


@router.get("/{name}", response_model=CredentialOut)
def get(name: str, _: str = Depends(require_scope("credentials:read"))):
    try:
        return get_credential(name)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.get("/{name}/reveal", response_model=CredentialSecret)
def reveal(name: str, actor: str = Depends(require_scope("credentials:reveal"))):
    try:
        return reveal_credential(name, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.get("/{name}/history", response_model=list[RotationLogOut])
def history(name: str, _: str = Depends(require_scope("credentials:read"))):
    try:
        return get_credential_history(name)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.post("/{name}/rollback", response_model=CredentialOut)
def rollback(
    name: str,
    rotation_id: str = Query(..., description="要回滚到的轮换版本 ID"),
    actor: str = Depends(require_scope("credentials:write")),
):
    try:
        return rollback_credential(name, rotation_id, actor=actor)
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.patch("/{name}", response_model=CredentialOut)
def update(name: str, body: CredentialUpdate, actor: str = Depends(require_scope("credentials:write"))):
    try:
        return update_credential(name, body, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.post("/{name}/rotate", response_model=CredentialOut)
def rotate(
    name: str,
    body: RotateRequest,
    actor: str = Depends(require_scope("credentials:write")),
):
    """轮换凭证值。明文经请求体传输，避免出现在 URL/访问日志中。"""
    try:
        return rotate_credential(name, body.new_value, body.note, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.delete("/{name}", response_model=MessageOut)
def delete(name: str, actor: str = Depends(require_scope("credentials:write"))):
    try:
        delete_credential(name, actor=actor)
        return MessageOut(message="deleted")
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.get("/{name}/health")
def health_check(name: str, actor: str = Depends(require_scope("credentials:reveal"))):
    """凭证健康检查：密码强度 + 跨凭证重复检测。

    需 reveal 权限，因为重复检测会 reveal 其他凭证的明文用于比对。
    """
    from ..store import reveal_credential as _reveal, list_credentials as _list
    from ..crypto import password_strength
    try:
        secret = _reveal(name, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")
    strength = password_strength(secret.value)
    duplicates = []
    all_creds = _list()
    for c in all_creds:
        if c.name == name:
            continue
        try:
            other = _reveal(c.name, actor=actor)
            if other.value == secret.value:
                duplicates.append(c.name)
        except Exception:
            pass
    return {
        "name": name,
        "type": secret.type.value,
        "strength": strength,
        "duplicates": duplicates,
        "has_duplicates": len(duplicates) > 0,
    }
