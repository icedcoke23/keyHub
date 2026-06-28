#!/usr/bin/env bash
# KeyHub pre-commit hook —— 防止明文密钥提交
#
# 安装方式（二选一）：
#   方式 A（推荐，需 pip install pre-commit）:
#     pre-commit install
#   方式 B（纯 shell，无需依赖）:
#     cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
#     chmod +x .git/hooks/pre-commit
#
# 若未安装 gitleaks，hook 会退化为基于 grep 的基础扫描。

set -euo pipefail

# 仅扫描暂存区文件
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -vE '\.git/' || true)
[ -z "$FILES" ] && exit 0

# 高危模式：OpenAI / Anthropic / GitHub PAT / PEM 私钥 / AWS
# 注意：使用 ERE（grep -E），花括号量词无需转义
PATTERNS=(
  'sk-[A-Za-z0-9]{40,}'
  'sk-ant-[A-Za-z0-9_-]{80,}'
  'gh[pousr]_[A-Za-z0-9]{36,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
)
# 通用模式（大小写不敏感）：api_key=xxx / secret: xxx 等（支持可选引号包裹值）
GENERIC_PATTERN='(api[_-]?key|secret|token|password)[[:space:]]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9_-]{20,}'

if command -v gitleaks >/dev/null 2>&1; then
  # 使用 gitleaks 扫描暂存区
  gitleaks protect --staged --config .gitleaks.toml --redact -v
  exit $?
fi

# 退化方案：grep 扫描
echo "[keyhub-hook] gitleaks 未安装，使用基础 grep 扫描（建议安装: pip install gitleaks)" >&2
HITS=0
for f in $FILES; do
  [ -f "$f" ] || continue
  case "$f" in
    .env.example|README.md|SECURITY.md|CONTRIBUTING.md|.gitleaks.toml|.pre-commit-config.yaml|scripts/pre-commit-hook.sh|tests/*) continue ;;
  esac
  for pat in "${PATTERNS[@]}"; do
    if grep -nE "$pat" "$f" >/dev/null 2>&1; then
      echo "[keyhub-hook] 疑似密钥在 $f:" >&2
      grep -nE "$pat" "$f" | head -3 >&2 || true
      HITS=$((HITS+1))
    fi
  done
  # 通用模式（大小写不敏感）
  if grep -niE "$GENERIC_PATTERN" "$f" >/dev/null 2>&1; then
    echo "[keyhub-hook] 疑似赋值型密钥在 $f:" >&2
    grep -niE "$GENERIC_PATTERN" "$f" | head -3 >&2 || true
    HITS=$((HITS+1))
  fi
done

if [ "$HITS" -gt 0 ]; then
  echo "" >&2
  echo "[keyhub-hook] 检测到 $HITS 处疑似明文密钥，提交已阻止。" >&2
  echo "[keyhub-hook] 若确认为误报，请将文件加入 .gitleaks.toml 的 allowlist 后重试。" >&2
  exit 1
fi

exit 0
