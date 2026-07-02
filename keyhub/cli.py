"""KeyHub 命令行工具。

直接操作本地数据库（无需启动服务），适合个人自用场景。
对于需要远程访问的场景，使用 REST API / API Token。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .config import get_settings
from .db import init_db, session_scope
from .runtime import get_runtime

app = typer.Typer(no_args_is_help=True, help="KeyHub — 个人密钥与 LLM 凭证管理")
console = Console()


def _ensure_unlocked():
    """确保已解锁；未解锁则提示输入主密码。"""
    rt = get_runtime()
    if not rt.is_initialized():
        console.print("[red]KeyHub 尚未初始化，请先运行 [bold]keyhub init[/bold][/red]")
        raise typer.Exit(1)
    if rt.unlocked:
        return
    pw = os.environ.get("KEYHUB_MASTER_PASSWORD") or Prompt.ask(
        "主密码", password=True
    )
    if not rt.unlock(pw):
        console.print("[red]主密码错误[/red]")
        raise typer.Exit(1)
    console.print("[green]已解锁[/green]")


# ===== init =====

@app.command()
def init():
    """首次初始化：设置主密码。"""
    rt = get_runtime()
    init_db()
    if rt.is_initialized():
        console.print("[yellow]已初始化过[/yellow]")
        raise typer.Exit(0)
    env_pw = os.environ.get("KEYHUB_MASTER_PASSWORD")
    if env_pw:
        pw = env_pw
        if len(pw) < 8:
            console.print("[red]密码至少 8 位[/red]")
            raise typer.Exit(1)
        console.print("[dim]从 KEYHUB_MASTER_PASSWORD 环境变量读取主密码[/dim]")
    else:
        pw = Prompt.ask("设置主密码（至少 8 位）", password=True)
        pw2 = Prompt.ask("确认主密码", password=True)
        if pw != pw2:
            console.print("[red]两次输入不一致[/red]")
            raise typer.Exit(1)
        if len(pw) < 8:
            console.print("[red]密码至少 8 位[/red]")
            raise typer.Exit(1)
    rt.initialize(pw)
    console.print("[green]初始化完成。主密码无法找回，请妥善保管。[/green]")


# ===== serve =====

@app.command()
def serve(
    host: Optional[str] = typer.Option(None, help="监听地址"),
    port: Optional[int] = typer.Option(None, help="监听端口"),
):
    """启动 API + Web UI 服务。"""
    settings = get_settings()
    init_db()
    rt = get_runtime()
    if not rt.is_initialized():
        console.print("[red]未初始化，请先运行 [bold]keyhub init[/bold][/red]")
        raise typer.Exit(1)
    if not rt.unlocked:
        pw = os.environ.get("KEYHUB_MASTER_PASSWORD") or Prompt.ask("主密码", password=True)
        if not rt.unlock(pw):
            console.print("[red]主密码错误[/red]")
            raise typer.Exit(1)
    h = host or settings.host
    p = port or settings.port
    console.print(f"[green]KeyHub 启动于 http://{h}:{p}[/green]")
    import uvicorn
    uvicorn.run("keyhub.main:app", host=h, port=p, reload=False)


# ===== set =====

@app.command(name="set")
def set_(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="凭证名称"),
    type: str = typer.Option("password", "--type", "-t", help="password/token/ssh_key/database/llm/other"),
    value: Optional[str] = typer.Option(None, "--value", "-v", help="明文值；未提供则交互输入"),
    provider: Optional[str] = typer.Option(None, "--provider", help="LLM 供应商"),
    label: Optional[str] = typer.Option(None, "--label", help="LLM 标签"),
    rotation_days: Optional[int] = typer.Option(None, "--rotation-days", help="建议轮换周期"),
    metadata: Optional[str] = typer.Option(None, "--metadata", help="JSON 元数据"),
):
    """新增凭证。"""
    _ensure_unlocked()
    from .models import CredentialType
    from .schemas import CredentialCreate
    from .store import create_credential

    val = value or Prompt.ask("明文值", password=True)
    try:
        ct = CredentialType(type)
    except ValueError:
        console.print(f"[red]未知类型: {type}[/red]")
        raise typer.Exit(1)
    md = json.loads(metadata) if metadata else {}
    try:
        out = create_credential(CredentialCreate(
            name=name, type=ct, value=val, provider=provider, label=label,
            rotation_days=rotation_days, metadata=md,
        ))
        console.print(f"[green]已创建 {out.name} (id={out.id})[/green]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


# ===== get =====

@app.command()
def get(
    name: str = typer.Argument(..., help="凭证名称"),
    reveal: bool = typer.Option(False, "--reveal", "-r", help="显示明文"),
):
    """查看凭证。默认不显示明文。"""
    _ensure_unlocked()
    from .store import get_credential, reveal_credential

    try:
        c = get_credential(name)
    except KeyError:
        console.print(f"[red]凭证 '{name}' 不存在[/red]")
        raise typer.Exit(1)
    table = Table(show_header=False)
    table.add_column("k", style="cyan")
    table.add_column("v")
    table.add_row("name", c.name)
    table.add_row("type", c.type.value)
    table.add_row("provider", c.provider or "-")
    table.add_row("label", c.label or "-")
    table.add_row("expires_at", str(c.expires_at or "-"))
    table.add_row("rotation_days", str(c.rotation_days or "-"))
    table.add_row("last_rotated", str(c.last_rotated_at or "-"))
    if reveal:
        try:
            s = reveal_credential(name)
            table.add_row("value", s.value)
        except Exception as e:
            table.add_row("value", f"[red]解密失败: {e}[/red]")
    else:
        table.add_row("value", "[dim](使用 --reveal 显示)[/dim]")
    console.print(table)


# ===== list =====

@app.command(name="list")
def list_(
    type: Optional[str] = typer.Option(None, "--type", "-t"),
):
    """列出所有凭证（不显示明文）。"""
    _ensure_unlocked()
    from .models import CredentialType
    from .store import list_credentials

    tf = None
    if type:
        try:
            tf = CredentialType(type)
        except ValueError:
            console.print(f"[red]未知类型: {type}[/red]")
            raise typer.Exit(1)
    rows = list_credentials(type_filter=tf)
    table = Table()
    table.add_column("名称")
    table.add_column("类型")
    table.add_column("供应商/标签")
    table.add_column("状态")
    table.add_column("到期")
    table.add_column("上次轮换")
    for c in rows:
        table.add_row(
            c.name,
            c.type.value,
            f"{c.provider}/{c.label}" if c.provider else "-",
            c.llm_status.value if c.llm_status else "-",
            str(c.expires_at.date()) if c.expires_at else "-",
            str(c.last_rotated_at.date()) if c.last_rotated_at else "-",
        )
    console.print(table)


# ===== rotate =====

@app.command()
def rotate(
    name: str = typer.Argument(..., help="凭证名称"),
    new_value: Optional[str] = typer.Option(None, "--value", "-v"),
    note: Optional[str] = typer.Option(None, "--note"),
):
    """轮换凭证值。"""
    _ensure_unlocked()
    from .store import rotate_credential

    val = new_value or Prompt.ask("新明文值", password=True)
    try:
        out = rotate_credential(name, val, note)
        console.print(f"[green]已轮换 {out.name}，上次轮换: {out.last_rotated_at}[/green]")
    except KeyError:
        console.print(f"[red]凭证 '{name}' 不存在[/red]")
        raise typer.Exit(1)


# ===== delete =====

@app.command()
def delete(
    name: str = typer.Argument(..., help="凭证名称"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """删除凭证（软删除）。"""
    _ensure_unlocked()
    from .store import delete_credential
    if not yes:
        if not typer.confirm(f"确认删除 '{name}'？"):
            raise typer.Exit(0)
    try:
        delete_credential(name)
        console.print(f"[green]已删除 {name}[/green]")
    except KeyError:
        console.print(f"[red]凭证 '{name}' 不存在[/red]")
        raise typer.Exit(1)


# ===== llm =====

@app.command()
def llm(
    ctx: typer.Context,
):
    """LLM 相关操作。子命令：chat / keys / usage / cost"""
    console.print("用法: keyhub llm-chat / keyhub llm-keys / keyhub llm-usage")
    raise typer.Exit(0)


@app.command(name="llm-chat")
def llm_chat(
    provider: str = typer.Option(..., "--provider", "-p"),
    model: str = typer.Option(..., "--model", "-m"),
    message: str = typer.Argument(..., help="用户消息"),
):
    """通过代理调用 LLM。"""
    _ensure_unlocked()
    from .llm.proxy import chat, LLMProxyError
    try:
        r = chat(provider=provider, model=model, messages=[{"role": "user", "content": message}])
        text = r.get("choices", [{}])[0].get("message", {}).get("content") if "choices" in r else r.get("content", [{}])[0].get("text", "")
        console.print(text or json.dumps(r, ensure_ascii=False, indent=2))
    except LLMProxyError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@app.command(name="llm-keys")
def llm_keys(
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
):
    """列出 LLM key 状态。"""
    _ensure_unlocked()
    from .llm.tracker import list_llm_keys
    rows = list_llm_keys(provider=provider)
    table = Table()
    table.add_column("供应商")
    table.add_column("标签")
    table.add_column("状态")
    table.add_column("请求数")
    table.add_column("成本($)")
    table.add_column("冷却至")
    for k in rows:
        table.add_row(
            k.provider, f"{k.label} ({k.name})", k.status.value,
            str(k.total_requests), f"{k.estimated_cost_usd:.4f}",
            str(k.cooldown_until or "-"),
        )
    console.print(table)


@app.command(name="llm-usage")
def llm_usage(
    limit: int = typer.Option(20, "--limit", "-n"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
):
    """查看 LLM 调用记录。"""
    _ensure_unlocked()
    from .llm.tracker import list_usage
    rows = list_usage(limit=limit, provider=provider)
    table = Table()
    table.add_column("时间")
    table.add_column("Key")
    table.add_column("模型")
    table.add_column("token")
    table.add_column("成本")
    table.add_column("结果")
    for u in rows:
        table.add_row(
            str(u.created_at)[:19],
            f"{u.provider}/{u.label}",
            u.model,
            f"{u.prompt_tokens}/{u.completion_tokens}",
            f"${u.cost_usd:.5f}",
            "ok" if u.success else "fail",
        )
    console.print(table)


@app.command(name="rotation-check")
def rotation_check():
    """检查需要轮换的凭证。"""
    _ensure_unlocked()
    from .rotation import get_checker
    rs = get_checker().check_once()
    if not rs:
        console.print("[green]无需轮换的凭证[/green]")
        return
    table = Table()
    table.add_column("名称")
    table.add_column("类型")
    table.add_column("距到期")
    table.add_column("上次轮换")
    for r in rs:
        table.add_row(
            r.name, r.type.value,
            f"{r.days_until_expire}天" if r.days_until_expire is not None else "-",
            f"{r.days_since_rotation}天前" if r.days_since_rotation is not None else "从未",
        )
    console.print(table)


@app.command(name="change-password")
def change_password(
    old: Optional[str] = typer.Option(None, "--old", "-o", help="旧主密码；不提供则交互输入"),
    new: Optional[str] = typer.Option(None, "--new", "-n", help="新主密码；不提供则交互输入"),
):
    """变更主密码（重新加密所有凭证）。"""
    rt = get_runtime()
    if not rt.is_initialized():
        console.print("[red]未初始化[/red]")
        raise typer.Exit(1)
    if not rt.unlocked:
        old_pw = old or os.environ.get("KEYHUB_MASTER_PASSWORD") or Prompt.ask("旧主密码", password=True)
        if not rt.unlock(old_pw):
            console.print("[red]旧主密码错误[/red]")
            raise typer.Exit(1)
        old = old_pw
    else:
        if not old:
            old = Prompt.ask("旧主密码（验证）", password=True)
    new_pw = new or Prompt.ask("新主密码（至少 8 位）", password=True)
    new_pw2 = Prompt.ask("确认新主密码", password=True)
    if new_pw != new_pw2:
        console.print("[red]两次新密码不一致[/red]")
        raise typer.Exit(1)
    try:
        n = rt.change_master_password(old, new_pw)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]主密码已变更，重新加密 {n} 条凭证[/green]")
    # 记审计
    from .audit import record as audit_record
    from .models import AuditAction
    audit_record(AuditAction.auth_password_change, "master",
                 detail={"reencrypted": n})


@app.command(name="token-create")
def token_create(
    name: str = typer.Argument(..., help="Token 名称"),
    hours: Optional[int] = typer.Option(None, "--hours", help="有效期（小时）"),
):
    """创建 API Token（程序化访问）。"""
    _ensure_unlocked()
    from .auth import create_token
    raw, _ = create_token(name, ["*"], hours)
    console.print("[green]API Token（仅显示一次）:[/green]")
    console.print(f"[bold]{raw}[/bold]")
    console.print("\n使用方式: curl -H 'Authorization: Bearer <token>' http://localhost:8000/api/credentials")


@app.command(name="notify-test")
def notify_test():
    """发送一条测试通知（Webhook / 邮件 / 控制台）。"""
    from .notify import get_notifier
    get_notifier().notify("test.notification", {"message": "this is a test from KeyHub CLI"})
    console.print("[green]测试通知已发送（查看控制台输出 / Webhook / 邮箱）[/green]")


@app.command(name="backup-export")
def backup_export(
    output: str = typer.Argument(..., help="输出文件路径（.khbak）"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="备份密码；不提供则交互输入"),
):
    """导出所有凭证到加密备份文件（.khbak）。

    备份密码独立于主密码，建议使用不同的强密码。
    """
    _ensure_unlocked()
    from .backup import export_backup
    pw = password or Prompt.ask("备份密码（用于加密备份文件）", password=True)
    if not password:  # 仅交互输入时要求二次确认
        pw2 = Prompt.ask("确认备份密码", password=True)
        if pw != pw2:
            console.print("[red]两次密码不一致[/red]")
            raise typer.Exit(1)
    if len(pw) < 8:
        console.print("[red]备份密码至少 8 位[/red]")
        raise typer.Exit(1)
    result = export_backup(output, pw)
    console.print(f"[green]已导出 {result['count']} 条凭证到 {result['path']}[/green]")
    console.print("[yellow]请妥善保管备份文件与密码；该文件含所有凭证明文。[/yellow]")


@app.command(name="backup-import")
def backup_import(
    input_path: str = typer.Argument(..., help="备份文件路径（.khbak）"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="备份密码"),
    overwrite: bool = typer.Option(False, "--overwrite", help="覆盖同名凭证"),
):
    """从加密备份文件导入凭证。"""
    _ensure_unlocked()
    from .backup import import_backup
    pw = password or Prompt.ask("备份密码", password=True)
    try:
        result = import_backup(input_path, pw, overwrite=overwrite)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]导入完成：新增 {result['imported']}，跳过 {result['skipped']}，"
        f"覆盖 {result['overwritten']}（备份内共 {result['total_in_backup']} 条）[/green]"
    )


@app.command(name="gen-password")
def gen_password(
    length: int = typer.Option(20, "--length", help="密码长度"),
    symbols: bool = typer.Option(True, "--symbols/--no-symbols"),
    exclude_similar: bool = typer.Option(True, "--exclude-similar/--include-similar"),
):
    """生成强密码。"""
    from .crypto import generate_password, password_strength
    pw = generate_password(length=length, symbols=symbols, exclude_similar=exclude_similar)
    s = password_strength(pw)
    console.print(f"[bold green]{pw}[/bold green]")
    console.print(f"强度: {s['label']} (熵: {s['entropy_bits']} bits)")


@app.command(name="health-check")
def health_check(name: str = typer.Argument(..., help="凭证名称")):
    """检查凭证强度、重复使用情况。"""
    _ensure_unlocked()
    from .store import reveal_credential, list_credentials
    from .crypto import password_strength
    try:
        secret = reveal_credential(name, actor="health-check")
    except KeyError:
        console.print(f"[red]凭证 '{name}' 不存在[/red]")
        raise typer.Exit(1)
    strength = password_strength(secret.value)
    colors = {0: "red", 1: "red", 2: "yellow", 3: "green", 4: "green"}
    table = Table(show_header=False)
    table.add_column("k", style="cyan")
    table.add_column("v")
    table.add_row("凭证", name)
    table.add_row("类型", secret.type.value)
    table.add_row("强度", f"[{colors.get(strength['score'], 'white')}]{strength['label']}[/{colors.get(strength['score'], 'white')}]")
    table.add_row("熵(bits)", f"{strength['entropy_bits']:.1f}")
    if strength["issues"]:
        table.add_row("问题", "\n".join(strength["issues"]))
    # 重复检测
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
    if duplicates:
        table.add_row("重复使用", "[red]" + ", ".join(duplicates) + "[/red]")
    else:
        table.add_row("重复使用", "[green]无[/green]")
    console.print(table)


@app.command(name="totp-generate")
def totp_generate(
    account: str = typer.Argument(..., help="账户标识（如邮箱）"),
    issuer: str = typer.Option("KeyHub", "--issuer", help="发行者名称"),
):
    """生成 TOTP 密钥（用于 2FA）。"""
    from .crypto import generate_totp_secret, generate_totp_uri
    secret = generate_totp_secret()
    uri = generate_totp_uri(secret, account, issuer)
    console.print("[green]TOTP 密钥（请安全保存）：[/green]")
    console.print(f"[bold]{secret}[/bold]")
    console.print(f"\n[dim]otpauth URI（可生成二维码）：[/dim]")
    console.print(f"[dim]{uri}[/dim]")
    console.print("\n[yellow]⚠ 此密钥仅显示一次，请立即保存到安全位置。[/yellow]")


# ===== proxy =====

alias_app = typer.Typer(help="模型别名管理")
app.add_typer(alias_app, name="alias")


@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="绑定地址"),
    port: int = typer.Option(8080, "--port", "-p", help="监听端口"),
    upstream: str = typer.Option("http://127.0.0.1:8000", "--upstream", "-u", help="KeyHub 服务地址"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="API Token（默认从 KEYHUB_TOKEN 环境变量读取）"),
):
    """启动本地 HTTP 代理服务器（绑定 127.0.0.1:8080），将 OpenAI 格式请求转发到 KeyHub。"""
    import uvicorn
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response, StreamingResponse
    import httpx

    api_token = token or os.environ.get("KEYHUB_TOKEN")
    if not api_token:
        console.print("[yellow]警告: 未设置 API Token（使用 --token 或 KEYHUB_TOKEN 环境变量）[/yellow]")

    proxy_fastapi = FastAPI()

    @proxy_fastapi.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    async def proxy_v1(path: str, request: Request):
        nonlocal api_token
        url = f"{upstream.rstrip('/')}/v1/{path}"
        headers = dict(request.headers)
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        headers.pop("host", None)

        body = await request.body()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as client:
                is_stream = False
                if path == "chat/completions":
                    try:
                        import json
                        body_json = json.loads(body)
                        is_stream = bool(body_json.get("stream", False))
                    except Exception:
                        pass

                if is_stream:
                    async def stream_generator():
                        async with client.stream(
                            method=request.method,
                            url=url,
                            headers=headers,
                            content=body,
                        ) as resp:
                            async for chunk in resp.aiter_bytes():
                                yield chunk
                    return StreamingResponse(
                        stream_generator(),
                        media_type="text/event-stream",
                        status_code=200,
                    )

                resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    media_type=resp.headers.get("content-type", "application/json"),
                )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=503,
                content={"error": {"message": f"无法连接到 KeyHub 服务: {upstream}", "type": "connection_error"}},
            )
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": {"message": str(e), "type": "proxy_error"}},
            )

    @proxy_fastapi.get("/healthz")
    async def proxy_healthz():
        return {"status": "ok", "proxy": "keyhub-proxy"}

    console.print(f"[green]KeyHub 代理启动于 http://{host}:{port}[/green]")
    console.print(f"[dim]上游: {upstream}[/dim]")
    console.print(f"[dim]使用方式: OPENAI_BASE_URL=http://{host}:{port}/v1[/dim]")
    uvicorn.run(proxy_fastapi, host=host, port=port, log_level="warning")


# ===== alias =====

@alias_app.command("add")
def alias_add(
    alias: str = typer.Argument(..., help="别名（如 gpt-4）"),
    provider: str = typer.Option(..., "--provider", "-p", help="供应商（如 openai）"),
    model: str = typer.Option(..., "--model", "-m", help="实际模型名（如 gpt-4-turbo）"),
):
    """添加模型别名。"""
    _ensure_unlocked()
    from .llm.aliases import get_alias_manager
    mgr = get_alias_manager()
    mgr.add_alias(alias, provider, model)
    console.print(f"[green]已添加别名: {alias} -> {provider}/{model}[/green]")


@alias_app.command("remove")
def alias_remove(
    alias: str = typer.Argument(..., help="要删除的别名"),
):
    """删除模型别名。"""
    _ensure_unlocked()
    from .llm.aliases import get_alias_manager
    mgr = get_alias_manager()
    if mgr.remove_alias(alias):
        console.print(f"[green]已删除别名: {alias}[/green]")
    else:
        console.print(f"[yellow]别名 '{alias}' 不存在[/yellow]")


@alias_app.command("list")
def alias_list():
    """列出所有模型别名。"""
    _ensure_unlocked()
    from .llm.aliases import get_alias_manager, PRESETS
    mgr = get_alias_manager()
    aliases = mgr.list_aliases()

    table = Table(title="模型别名")
    table.add_column("别名", style="cyan")
    table.add_column("->", style="dim")
    table.add_column("供应商", style="green")
    table.add_column("模型", style="green")

    for a, (p, m) in aliases.items():
        table.add_row(a, "->", p, m)

    if not aliases:
        console.print("[dim]暂无自定义别名[/dim]")
    else:
        console.print(table)

    console.print("\n[dim]预设别名:[/dim]")
    for a, (p, m) in PRESETS.items():
        console.print(f"  [dim]{a} -> {p}/{m}[/dim]")


if __name__ == "__main__":
    app()
