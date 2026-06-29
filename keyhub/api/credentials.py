"""凭证 CRUD 路由。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..models import CredentialType
from ..schemas import (
    CredentialCreate,
    CredentialOut,
    CredentialSecret,
    CredentialUpdate,
    MessageOut,
)
from ..store import (
    create_credential,
    delete_credential,
    get_credential,
    list_credentials,
    reveal_credential,
    rotate_credential,
    update_credential,
)
from ..auth import require_auth, require_scope

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


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


@router.get("/{name}", response_model=CredentialOut)
def get(name: str, _: str = Depends(require_scope("credentials:read"))):
    try:
        return get_credential(name)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.get("/{name}/reveal", response_model=CredentialSecret)
def reveal(name: str, actor: str = Depends(require_scope("credentials:reveal"))):
    """返回明文 —— 谨慎使用，会被记入审计日志。"""
    try:
        return reveal_credential(name, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.patch("/{name}", response_model=CredentialOut)
def update(name: str, body: CredentialUpdate, actor: str = Depends(require_scope("credentials:write"))):
    try:
        return update_credential(name, body, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.post("/{name}/rotate", response_model=CredentialOut)
def rotate(
    name: str,
    new_value: str = Query(..., description="new plaintext value"),
    note: str | None = Query(None),
    actor: str = Depends(require_scope("credentials:write")),
):
    try:
        return rotate_credential(name, new_value, note, actor=actor)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.delete("/{name}", response_model=MessageOut)
def delete(name: str, actor: str = Depends(require_scope("credentials:write"))):
    try:
        delete_credential(name, actor=actor)
        return MessageOut(message="deleted")
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


# ===== 凭证健康检查 =====

@router.get("/{name}/health")
def health_check(name: str, _: str = Depends(require_scope("credentials:read"))):
    """检查凭证强度、重复使用。"""
    from ..store import reveal_credential, list_credentials
    from ..crypto import password_strength
    try:
        secret = reveal_credential(name, actor="health-check")
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")
    strength = password_strength(secret.value)
    duplicates = []
    all_creds = list_credentials()
    for c in all_creds:
        if c.name == name:
            continue
        try:
            other = reveal_credential(c.name, actor="health-check")
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

# ===== 密码生成器 =====

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
    """生成密码学安全的随机密码。"""
    from ..crypto import generate_password as gen_pw, password_strength
    pw = gen_pw(length=length, upper=upper, lower=lower, digits=digits,
                symbols=symbols, exclude_similar=exclude_similar)
    return {"password": pw, "strength": password_strength(pw)}

# ===== 批量导入 =====

@router.post("/import")
def import_credentials(items: list[dict], actor: str = Depends(require_scope("credentials:write"))):
    """批量导入凭证。"""
    from ..schemas import CredentialCreate
    from ..store import create_credential
    from ..models import AuditAction
    from ..audit import record as audit_record
    results = {"imported": 0, "skipped": 0, "errors": []}
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
            results["errors"].append({"name": item.get("name", "?"), "error": str(e)})
    audit_record(AuditAction.credential_import, actor, detail=results)
    return results
