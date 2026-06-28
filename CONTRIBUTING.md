# 贡献指南

## 安全规则（必须遵守）

KeyHub 是密钥管理项目，安全是第一优先级。贡献者**必须**遵守以下规则：

### 禁止事项

1. **永远不要**在代码、注释、commit message、issue、PR 中写入真实密钥
2. **永远不要**提交以下文件（已被 `.gitignore` 排除）：
   - `.env` / `.env.local` / `.env.*.local`
   - `data/` 目录下的任何文件（含 `*.db` 数据库）
   - `*.key` / `*.pem` / `*.p12` / `*.pfx`
   - `secrets/` 目录
   - `master.key`
3. **永远不要**在测试中使用真实密钥，测试用的假 key 必须形如 `sk-test-xxx`、`khub_xxx`
4. **永远不要**禁用或绕过 gitleaks pre-commit hook

### 提交前检查

提交前请确保：

```bash
# 1. 已安装 pre-commit hooks
pip install pre-commit
pre-commit install

# 2. 手动扫描（可选）
gitleaks detect --config .gitleaks.toml --source .

# 3. 代码风格
ruff check keyhub
```

若 hook 误报，请将文件加入 `.gitleaks.toml` 的 `allowlist`，**不要**用 `--no-verify` 绕过。

### 密钥泄露应急

如果不慎提交了真实密钥：

1. **立即吊销**该密钥（在对应供应商后台）
2. 不要仅删除文件再提交 —— 历史记录中仍存在，需用 `git filter-repo` 清理
3. 通知仓库维护者
4. 审计该密钥是否被滥用

## 开发流程

1. Fork 仓库并创建分支
2. 编写代码与测试
3. 确保所有测试通过：`python tests/smoke_test.py`
4. 提交 PR，描述变更与动机

## 代码风格

- Python 3.11+，使用 `from __future__ import annotations`
- 行宽 100 字符（ruff 配置）
- 类型注解：所有公开函数必须带类型注解
- 注释：仅在逻辑不自明处添加，描述「为什么」而非「是什么」
- 安全敏感操作必须记审计日志（见 `keyhub/audit.py`）

## 测试

```bash
# 端到端冒烟测试（加密、CRUD、负载均衡、用量、轮换）
python tests/smoke_test.py
```

新增功能应补充对应的冒烟测试用例。
