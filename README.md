# KeyHub

个人密钥与大模型 API 凭证管理仓库 —— 加密存储、代理转发、负载均衡、用量监控、轮换提醒。

## 特性

- **加密存储**：AES-256-GCM 加密，主密钥由主密码经 Argon2id 派生，永不落盘
- **双类凭证**：常规密码（Web/DB/SSH/Token）+ 大模型 API Key（OpenAI/Anthropic/DeepSeek/Qwen/GLM …）
- **代理转发**：KeyHub 作为 LLM 请求代理，下游应用不接触真实 key
- **多 key 负载均衡**：同一供应商多 key 轮询/故障转移，突破单 key 限额
- **用量监控**：按 key 统计调用次数、token 消耗、成本估算
- **轮换提醒**：凭证到期前自动提醒，记录轮换历史
- **多入口**：REST API + CLI + Web UI

## 快速开始

### 安装

```bash
git clone <repo-url> keyhub && cd keyhub
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env
```

### 初始化

```bash
keyhub init          # 交互式设置主密码
```

### 启动服务

```bash
keyhub serve         # 启动 API + Web UI，默认 127.0.0.1:8000
```

### CLI 日常使用

```bash
keyhub set openai-main --type llm --provider openai       # 录入凭证
keyhub get openai-main                                    # 取回明文
keyhub list                                               # 列出所有凭证（不显示明文）
keyhub llm chat --provider openai --model gpt-4o          # 通过代理调用 LLM
keyhub rotate openai-main                                 # 轮换并记录历史
```

### Docker

```bash
docker compose up -d
```

## 架构

```
┌─────────────────────────────────────────────────────┐
│  CLI (Typer)  │  Web UI (Jinja2)  │  REST API       │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │   FastAPI App      │
              │  ┌──────────────┐  │
              │  │ Auth (Argon2)│  │
              │  ├──────────────┤  │
              │  │ Credential   │  │
              │  │   Store      │  │
              │  ├──────────────┤  │
              │  │ LLM Proxy    │◄──┐ 负载均衡 / 用量监控
              │  │  + Balancer  │  │ │
              │  └──────┬───────┘  │ │
              └─────────┼──────────┘ │
                        │            │
              ┌─────────▼──────┐  ┌──▼──────────┐
              │ AES-256-GCM    │  │  Upstream    │
              │   Crypto Layer │  │  LLM APIs    │
              └─────────┬──────┘  └─────────────┘
                        │
              ┌─────────▼──────┐
              │   SQLite       │
              │  (encrypted)   │
              └────────────────┘
```

## 安全

详见 [SECURITY.md](SECURITY.md)。

**核心原则**：主密钥永不落盘；凭证明文仅在内存短暂存在；生产环境必须 HTTPS。

## License

UNLICENSED — 私有项目，保留所有权利。
