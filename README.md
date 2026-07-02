# KeyHub

> 个人/小团队自托管的密钥与大模型 API 凭证管理系统——加密存储、智能代理、负载均衡、用量监控、安全审计。

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-UNLICENSED-red.svg)]()

## 为什么需要 KeyHub？

当你拥有多个 LLM API Key（OpenAI / Anthropic / DeepSeek / Qwen / GLM …）需要在多个项目中共享使用时，直接将 Key 硬编码或写入配置文件存在以下风险：

- 🔑 **Key 泄露**：代码提交、日志打印、共享环境导致 Key 意外暴露
- 💰 **成本失控**：单个 Key 超额使用产生意外账单
- 🔄 **轮换困难**：Key 泄露后难以快速轮换、无法追溯泄露源头
- 📊 **黑盒调用**：无法统计哪个项目/IP 消耗了多少 token

KeyHub 作为中间代理层解决这些问题：应用永远只接触代理地址，真实 Key 加密存储在本地，支持多 Key 负载均衡、熔断降级、用量统计、审计追踪。

## ✨ 核心特性

### 🔐 安全存储

- **AES-256-GCM 加密**：所有凭证明文加密存储，密文包含认证标签防篡改
- **AAD 绑定加密（v1 格式）**：每个凭证密文绑定 ID+Name 作为关联数据，防止密文被跨凭证替换
- **Pepper 密钥混合**：服务端密钥（`KEYHUB_SECRET_KEY`）与主密码派生密钥 XOR 混合，即使数据库泄露也无法离线暴力破解
- **Argon2id 密钥派生**：内存成本 128MB，抗 GPU/ASIC 破解
- **主密钥零落盘**：主密钥仅在解锁后存在于内存，锁定后立即清零
- **自动空闲锁定**：超时无操作自动锁定，内存密钥清零

### 🤖 LLM 智能代理

- **OpenAI 兼容 API**：`/v1/chat/completions`、`/v1/models` 标准接口，下游应用零改造
- **多策略负载均衡**：Round Robin / Weighted / Latency-based / Cost-based / **Least-Used**
- **熔断器模式**：连续失败的 Key 自动进入熔断状态，半开探测恢复，避免向故障 Key 持续发请求
- **每 Key 限流**：RPM（每分钟请求数）/ TPM（每分钟 Token 数）滑动窗口限流
- **Priority/Fallback 降级链**：高优先级 Key 熔断后自动切换到低优先级 Key，支持跨 Provider 降级
- **Retry-After 智能重试**：尊重 Provider 返回的限流头，指数退避+抖动重试
- **模型别名映射**：支持 `gpt4` → `openai/gpt-4-turbo` 等别名，业务代码无需感知底层模型变更
- **响应缓存**：相同请求内存缓存，减少重复调用
- **流式响应**：SSE streaming 完整支持

### 📋 凭证管理

- **多类型凭证**：密码（Web/DB/SSH）、API Token、LLM Key、TOTP 密钥
- **版本历史与回滚**：每次轮换记录加密快照，一键回滚到任意历史版本
- **凭证健康检查**：密码强度评估、重复密码检测
- **多格式导入**：Bitwarden JSON、KeePass CSV、KeyHub JSON 批量导入
- **JSON/CSV 导出**：批量导出（含明文，需授权）
- **加密备份**：独立密码保护的二进制全库备份格式（KHBK01），灾难恢复友好
- **轮换提醒**：凭证到期前/超期未轮换自动提醒，支持 Webhook 通知

### 📊 可观测性

- **Prometheus 指标**：`/metrics` 端点暴露凭证数、Key 数、调用次数、Token 消耗、延迟 P50/P95/P99、错误率、熔断状态
- **实时审计日志**：所有敏感操作（解锁/查看明文/轮换/删除）记入审计日志，SSE 实时推送
- **结构化 JSON 日志**：stdout 输出 JSON 格式日志，便于日志聚合系统采集
- **用量追踪**：按 Key 维度统计调用次数、Token 消耗、成本估算
- **延迟统计**：按 Provider/Key 追踪 P50/P95/P99 请求延迟

### 🛠️ 多入口

- **Web UI**：浏览器控制台，支持凭证 CRUD、Playground 聊天、实时日志
- **REST API**：完整的 OpenAPI 文档（`/docs`）
- **CLI**：命令行管理、本地代理启动、模型别名管理
- **本地代理模式**：CLI 启动 `127.0.0.1:8080` 代理，应用指向该地址即可透明代理
- **PWA 支持**：manifest.json + SVG 图标，可添加到桌面

## 🚀 快速开始

### 方式一：Docker Compose（推荐）

```bash
git clone https://github.com/icedcoke23/keyHub.git && cd keyHub
cp .env.example .env
# 编辑 .env 设置 KEYHUB_SECRET_KEY（生产环境必须修改）
docker compose up -d
```

访问 http://127.0.0.1:8000 ，首次访问会引导设置主密码。

### 方式二：本地安装

```bash
git clone https://github.com/icedcoke23/keyHub.git && cd keyHub
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 初始化（设置主密码）
keyhub init

# 启动服务
keyhub serve
# 访问 http://127.0.0.1:8000
```

### 方式三：本地代理模式

```bash
# 先确保 keyhub serve 已在 8000 端口运行
keyhub proxy --port 8080

# 应用只需将 base_url 指向 http://127.0.0.1:8080/v1
# 例如：
# openai.base_url = "http://127.0.0.1:8080/v1"
# openai.api_key = "任意非空值"（真实 Key 由 KeyHub 管理）
```

## 📖 CLI 使用

```bash
# 凭证管理
keyhub set openai-main --type llm --provider openai --label prod   # 录入 LLM Key
keyhub set db-prod --type password --metadata url=prod-db:5432     # 录入密码
keyhub list                                                        # 列出所有凭证
keyhub get openai-main                                             # 查看凭证（默认隐藏明文）
keyhub get openai-main --reveal                                    # 查看明文
keyhub rotate openai-main --value "sk-new-key-xxx"                 # 轮换并记录历史
keyhub delete old-key                                              # 删除（软删除）

# LLM 相关
keyhub llm keys                    # 列出所有 LLM Key 状态
keyhub llm chat -p openai -m gpt-4o   # 通过代理聊天
keyhub llm usage                   # 查看用量统计
keyhub llm cost                    # 查看成本估算

# 模型别名
keyhub alias add gpt4 -p openai -m gpt-4-turbo
keyhub alias list
keyhub proxy --port 8080           # 启动本地代理

# 安全
keyhub change-password             # 变更主密码（自动重新加密所有凭证）
keyhub backup-export backup.khbk   # 加密备份
keyhub backup-import backup.khbk   # 从备份恢复
keyhub gen-password --length 24    # 生成强密码
keyhub health-check                # 检查凭证强度和重复使用
```

## 🔌 API 使用

### 认证

KeyHub 使用 Session Cookie 认证（浏览器）或 Bearer Token 认证（API 调用）：

```bash
# 创建 API Token
curl -X POST http://127.0.0.1:8000/api/auth/tokens \
  -H "Content-Type: application/json" \
  -b "keyhub_session=<session-cookie>" \
  -d '{"name": "my-app", "scope": "readonly"}'

# 使用 Token
curl http://127.0.0.1:8000/api/credentials \
  -H "Authorization: Bearer <token>"
```

### LLM 代理调用

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer <token-or-session>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'
```

### Prometheus 监控

```bash
curl http://127.0.0.1:8000/metrics
```

关键指标：
- `keyhub_credentials_total` - 凭证总数
- `keyhub_llm_keys_total` - LLM Key 总数
- `keyhub_llm_requests_total{provider,model,key_id,status}` - 调用计数
- `keyhub_llm_tokens_total{provider,model,key_id,type}` - Token 消耗
- `keyhub_llm_request_duration_seconds{provider,key_id}` - 请求延迟直方图
- `keyhub_llm_circuit_breaker_open{key_id}` - 熔断器状态

## 🏗️ 架构

```
┌──────────────────────────────────────────────────────────────┐
│  CLI (Typer)  │  Web UI (Jinja2)  │  REST API  │  Prometheus │
└────────────────────────┬─────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │     FastAPI App     │
              │ ┌─────────────────┐ │
              │ │ Auth            │ │  Argon2id / Session / Bearer Token
              │ ├─────────────────┤ │
              │ │ Credential Store│ │  CRUD / Versioning / Import/Export
              │ ├─────────────────┤ │
              │ │ LLM Proxy       │◄┼── Load Balancer / Circuit Breaker
              │ │  + Balancer     │ │  Rate Limiter / Retry / Cache
              │ ├─────────────────┤ │
              │ │ Audit / Metrics │ │  Structured Logging / SSE Events
              │ └────────┬────────┘ │
              └──────────┼──────────┘
                         │
              ┌──────────▼──────────┐
              │  AES-256-GCM v1     │  AAD绑定 / Pepper混合 / 压缩
              │  Crypto Layer       │
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │  SQLite (WAL 模式)   │  加密存储 / 自动迁移
              └─────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   Upstream LLM      │  OpenAI / Anthropic / DeepSeek / ...
              │   Provider APIs     │
              └─────────────────────┘
```

## ⚙️ 配置

所有配置通过环境变量或 `.env` 文件设置，主要配置项：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `KEYHUB_SECRET_KEY` | *(随机生成)* | Token/Session 签名密钥，生产环境**必须**设置 |
| `KEYHUB_ENV` | `development` | `development` / `production` |
| `KEYHUB_HOST` | `127.0.0.1` | 监听地址 |
| `KEYHUB_PORT` | `8000` | 监听端口 |
| `KEYHUB_DB_PATH` | `data/keyhub.db` | SQLite 数据库路径 |
| `KEYHUB_AUTO_LOCK_IDLE_SECONDS` | `1800` | 空闲自动锁定秒数，0=禁用 |
| `KEYHUB_TOKEN_RPM_LIMIT` | `60` | API Token 每分钟请求数限制 |
| `KEYHUB_LLM_BALANCE_STRATEGY` | `round_robin` | 负载均衡策略：round_robin/weighted/latency/cost/least_used |
| `KEYHUB_LLM_KEY_RPM_LIMIT` | `0` | 每 Key 每分钟请求数限制，0=不限 |
| `KEYHUB_LLM_KEY_TPM_LIMIT` | `0` | 每 Key 每分钟 Token 数限制，0=不限 |
| `KEYHUB_LLM_MAX_CONCURRENT` | `0` | LLM 最大并发请求数，0=不限 |
| `KEYHUB_LLM_CACHE_TTL` | `300` | 响应缓存 TTL（秒），0=禁用 |
| `KEYHUB_AUDIT_RETENTION_DAYS` | `0` | 审计日志保留天数，0=永久保留 |
| `KEYHUB_NOTIFY_WEBHOOK_URL` | *(空)* | Webhook 通知 URL |
| `KEYHUB_WEB_UI` | `true` | 是否启用 Web UI |

完整配置项见 [.env.example](.env.example)。

## 🔒 安全说明

详见 [SECURITY.md](SECURITY.md)。核心安全原则：

1. **主密钥零落盘**：主密钥仅在解锁后存在于内存，锁定/退出时立即清零
2. **Pepper 防数据库泄露**：`KEYHUB_SECRET_KEY` 不存储在数据库中，即使数据库文件泄露也无法暴力破解
3. **AAD 密文绑定**：每个凭证密文绑定上下文，防止密文被复制替换攻击
4. **作用域权限控制**：API Token 支持细粒度 scope（`credentials:read`/`credentials:reveal`/`admin:write` 等）
5. **登录限流**：基于 IP 的指数退避登录限流，防暴力破解
6. **审计全记录**：所有查看明文/轮换/删除操作均记入审计日志，不可篡改

**生产部署建议**：
- 使用 Docker 部署，映射 volume 持久化 data 目录
- 设置强 `KEYHUB_SECRET_KEY`（至少 32 字节随机值）
- 通过反向代理启用 HTTPS（nginx/Caddy）
- 绑定 `127.0.0.1` 而非 `0.0.0.0`，通过 SSH 隧道或内网访问
- 定期通过 `keyhub backup-export` 做加密备份

## 📁 项目结构

```
keyhub/
├── api/                    # REST API 路由
│   ├── auth.py            # 认证（初始化/解锁/锁定/Token管理）
│   ├── credentials.py     # 凭证 CRUD / 导入导出
│   ├── llm.py             # LLM Key 管理
│   ├── v1.py              # OpenAI 兼容 API（/v1/*）
│   ├── events.py          # SSE 实时事件流
│   ├── audit.py           # 审计日志查询
│   ├── rotation.py        # 轮换提醒
│   └── system.py          # 健康检查/备份恢复
├── llm/                   # LLM 代理核心
│   ├── proxy.py           # 请求代理/重试/流式
│   ├── balancer.py        # 负载均衡/熔断器/降级
│   ├── keylimit.py        # 每 Key 限流
│   ├── cache.py           # 响应缓存
│   ├── aliases.py         # 模型别名
│   ├── latency_stats.py   # 延迟统计
│   └── tracker.py         # 用量追踪
├── web/                   # Web UI
│   ├── templates/         # Jinja2 模板
│   └── static/            # JS/CSS/PWA manifest
├── crypto.py              # AES-256-GCM / Argon2id / TOTP / 密码生成
├── store.py               # 凭证数据访问层
├── backup.py              # 加密备份/恢复
├── importers.py           # Bitwarden/KeePass 导入
├── audit.py               # 审计日志
├── metrics.py             # Prometheus 指标
├── notify.py              # Webhook/邮件通知
├── cli.py                 # Typer CLI 入口
├── config.py              # 配置管理
├── db.py                  # 数据库引擎/Session
├── auth.py                # 认证/Session/Scope
└── main.py                # FastAPI 应用入口
```

## 🧪 开发

```bash
pip install -e ".[dev]"

# 运行测试
python -m pytest tests/ -v

# 启动开发服务器
KEYHUB_SECRET_KEY=dev-key python -m uvicorn keyhub.main:app --reload
```

## License

UNLICENSED — 私有项目，保留所有权利。
