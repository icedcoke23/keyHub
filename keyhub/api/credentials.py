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
    _: str = Depends(require_scope("credentials:read")),
):
    return list_credentials(type_filter=type)


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
