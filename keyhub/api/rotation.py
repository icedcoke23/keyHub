"""轮换提醒路由。"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import require_scope
from ..rotation import get_checker
from ..schemas import RotationReminder

router = APIRouter(prefix="/api/rotation", tags=["rotation"])


@router.get("/reminders", response_model=list[RotationReminder])
def reminders(_: str = Depends(require_scope("credentials:read"))):
    return get_checker().get_reminders()


@router.post("/check", response_model=list[RotationReminder])
def check_now(_: str = Depends(require_scope("credentials:read"))):
    return get_checker().check_once()
