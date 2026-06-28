"""Web UI：Jinja2 模板渲染 + 静态文件挂载。

UI 为单页应用风格的 server-rendered 页面，通过 fetch 调用 /api/*。
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..runtime import get_runtime

_WEB_DIR = Path(__file__).parent
_TEMPLATES = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


def mount_web_ui(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        rt = get_runtime()
        s = rt.status()
        # 未初始化 → 初始化页；未解锁 → 解锁页；已解锁 → 主面板
        if not s.initialized:
            return _TEMPLATES.TemplateResponse(
                request, "init.html", {"title": "初始化 KeyHub"}
            )
        if s.locked:
            return _TEMPLATES.TemplateResponse(
                request, "unlock.html", {"title": "解锁 KeyHub"}
            )
        return _TEMPLATES.TemplateResponse(
            request, "panel.html", {"title": "KeyHub 控制台"}
        )
