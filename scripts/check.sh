#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go node python3 git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '缺少检查所需命令：%s\n' "$cmd" >&2
    exit 127
  fi
done

TMP_ROOT="${TMPDIR:-/tmp}"
mkdir -p "$TMP_ROOT"
BUILD_DIR="$(mktemp -d "$TMP_ROOT/orangecat-check.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

printf '%s\n' '[1/7] Go 全量测试'
go test ./... -count=1

printf '%s\n' '[2/7] Go 静态检查'
go vet ./...

printf '%s\n' '[3/7] 编译面板'
go build -o "$BUILD_DIR/ocp-panel" ./panel/cmd/ocp-panel

printf '%s\n' '[4/7] 编译 Agent'
go build -o "$BUILD_DIR/ocp-agent" ./agent/cmd/ocp-agent

printf '%s\n' '[5/7] 检查嵌入页面 JavaScript'
python3 - "$ROOT_DIR/panel/cmd/ocp-panel/web/index.html" "$BUILD_DIR/ui-check.js" <<'PY'
from pathlib import Path
import re
import sys

html = Path(sys.argv[1]).read_text(encoding="utf-8")
scripts = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", html, flags=re.IGNORECASE | re.DOTALL)
if len(scripts) != 1:
    raise SystemExit("页面必须恰好包含一个内联 script 标签")
if "nonce=\"__OCP_CSP_NONCE__\"" not in html:
    raise SystemExit("内联脚本和样式必须保留 CSP nonce 占位符")
Path(sys.argv[2]).write_text(scripts[0], encoding="utf-8")
PY
node --check "$BUILD_DIR/ui-check.js"

printf '%s\n' '[6/7] 前端请求行为测试'
node --test panel/cmd/ocp-panel/web/index.test.mjs

printf '%s\n' '[7/7] Git 空白差异检查'
git diff --check

printf '%s\n' '本地门禁全部通过（本脚本不部署、不重启服务；部署由 installer/--apply 显式执行）。'
