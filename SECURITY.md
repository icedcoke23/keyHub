# Security Policy

## 报告漏洞

如果你发现 KeyHub 存在安全漏洞，请**不要**在公开 Issue 中提交。

请通过以下方式私密报告：
- 发送邮件至仓库维护者
- 在邮件中描述：影响范围、复现步骤、建议修复方案

收到报告后将在 72 小时内响应。

## 安全设计

KeyHub 采用以下安全机制：

### 凭证存储
- 所有凭证使用 **AES-256-GCM** 加密后存入数据库
- 主密钥由**主密码**经 **Argon2id** 派生，**永不落盘**
- 主密钥派生参数（salt、time_cost、memory_cost、parallelism）单独存储
- 数据库文件本身建议放在加密磁盘上

### 认证
- 主密码通过 Argon2 验证（不存储明文，不存储哈希外的任何形式）
- API Token 使用 HMAC 签名，可吊销
- Session Cookie 使用 `itsdangerous` 签名，`HttpOnly` + `SameSite=Strict`

### 内存
- 凭证明文仅在内存中短暂存在，使用后主动清零（`ctypes.memset`）
- 不记录任何凭证明文到日志

### 网络
- 生产环境必须通过 HTTPS 反向代理访问
- 代理转发 LLM 请求时不记录请求/响应体

## 禁止事项

- **永远不要**将 `.env`、`data/`、`*.db`、`*.key`、`*.pem` 提交到仓库
- **永远不要**在代码、注释、commit message 中写入真实密钥
- **永远不要**将 KeyHub 直接暴露到公网而不启用 HTTPS 与强主密码

## 暴露事件响应

如果主密码或数据库泄露：
1. 立即轮换**所有**存储在 KeyHub 中的凭证
2. 更改 KeyHub 主密码（需重新加密所有凭证）
3. 吊销所有已签发的 API Token
4. 审计访问日志
