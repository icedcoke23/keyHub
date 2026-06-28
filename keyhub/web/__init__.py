"""Web UI：Jinja2 模板渲染 + 静态文件挂载。

UI 为单页应用风格的 server-rendered 页面，通过 fetch 调用 /api/*。
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..auth import SESSION_COOKIE, verify_session
from ..runtime import get_runtime

_WEB_DIR = Path(__file__).parent
_TEMPLATES = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


def _has_valid_session(request: Request) -> bool:
    """检查请求是否携带有效 session cookie。"""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    return verify_session(token)


def mount_web_ui(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        rt = get_runtime()
        s = rt.status()
        # 未初始化 → 初始化页
        if not s.initialized:
            return _TEMPLATES.TemplateResponse(
                request, "init.html", {"title": "初始化 KeyHub"}
            )
        # 已初始化但未解锁，或已解锁但无有效 session → 解锁页
        # 后者避免 runtime 因环境变量自动解锁后，浏览器无 session 却渲染面板导致 API 401 循环
        if s.locked or not _has_valid_session(request):
            return _TEMPLATES.TemplateResponse(
                request, "unlock.html", {"title": "解锁 KeyHub"}
            )
        return _TEMPLATES.TemplateResponse(
            request, "panel.html", {"title": "KeyHub 控制台"}
        )
