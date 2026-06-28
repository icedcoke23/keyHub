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
    RotationReminder,
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
from ..auth import require_auth

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


@router.post("", response_model=CredentialOut)
def create(body: CredentialCreate, _: str = Depends(require_auth)):
    try:
        return create_credential(body)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("", response_model=list[CredentialOut])
def list_all(
    type: CredentialType | None = Query(None),
    _: str = Depends(require_auth),
):
    return list_credentials(type_filter=type)


@router.get("/{name}", response_model=CredentialOut)
def get(name: str, _: str = Depends(require_auth)):
    try:
        return get_credential(name)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.get("/{name}/reveal", response_model=CredentialSecret)
def reveal(name: str, _: str = Depends(require_auth)):
    """返回明文 —— 谨慎使用，会被记入审计日志（未来）。"""
    try:
        return reveal_credential(name)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.patch("/{name}", response_model=CredentialOut)
def update(name: str, body: CredentialUpdate, _: str = Depends(require_auth)):
    try:
        return update_credential(name, body)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.post("/{name}/rotate", response_model=CredentialOut)
def rotate(
    name: str,
    new_value: str = Query(..., description="new plaintext value"),
    note: str | None = Query(None),
    _: str = Depends(require_auth),
):
    try:
        return rotate_credential(name, new_value, note)
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")


@router.delete("/{name}", response_model=MessageOut)
def delete(name: str, _: str = Depends(require_auth)):
    try:
        delete_credential(name)
        return MessageOut(message="deleted")
    except KeyError:
        raise HTTPException(404, f"credential '{name}' not found")
