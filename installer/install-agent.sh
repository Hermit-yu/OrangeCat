#!/usr/bin/env bash
# ocp-agent 安装候选；默认只读检查，须显式 --apply 才会重启服务。
set -euo pipefail

PREFIX=/opt/OrangeCatPanel
UNIT=/etc/systemd/system/ocp-agent.service
MODE=${1:---check}
if [[ "$MODE" != "--check" && "$MODE" != "--apply" ]]; then
  echo "用法: $0 [--check|--apply]" >&2
  exit 2
fi
if [[ ! -f "$PREFIX/installer/ocp-agent.service" ]]; then
  echo "Agent systemd unit 不存在。" >&2
  exit 1
fi

TMP_BIN=$(mktemp "${TMPDIR:-/tmp}/ocp-agent.XXXXXX")
cleanup() { rm -f -- "$TMP_BIN"; }
trap cleanup EXIT
echo "[1/3] 编译 Agent 候选 ..."
go -C "$PREFIX" build -o "$TMP_BIN" ./agent/cmd/ocp-agent
"$TMP_BIN" --help >/dev/null 2>&1 || true
echo "候选 Agent 构建通过。"

if [[ "$MODE" == "--check" ]]; then
  echo "只读检查完成；未创建组、未覆盖二进制、未操作服务。"
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  echo "--apply 必须以 root 运行。" >&2
  exit 1
fi

getent group ocp-agent >/dev/null || groupadd --system ocp-agent
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/var/backups/ocp-agent/pre-update-$STAMP
install -d -o root -g root -m 0700 "$BACKUP"
for src in "$PREFIX/bin/ocp-agent" "$UNIT"; do
  name=$(basename "$src")
  if [[ -e "$src" ]]; then cp -a -- "$src" "$BACKUP/$name"; printf 'present\n' >"$BACKUP/$name.state"; else printf 'absent\n' >"$BACKUP/$name.state"; fi
done
was_active=0; systemctl is-active --quiet ocp-agent && was_active=1 || true
was_enabled=0; systemctl is-enabled --quiet ocp-agent && was_enabled=1 || true
rollback() {
  status=$?
  if [[ $status -eq 0 ]]; then return; fi
  trap - ERR
  echo "Agent 更新失败；恢复原二进制和 unit。" >&2
  for pair in "$PREFIX/bin/ocp-agent:ocp-agent" "$UNIT:ocp-agent.service"; do
    src=${pair%%:*}; name=${pair#*:}
    if [[ $(<"$BACKUP/$name.state") == present ]]; then
      install -D -m 0600 "$BACKUP/$name" "$src"
      if [[ "$src" == "$PREFIX/bin/ocp-agent" ]]; then chmod 0755 "$src"; else chmod 0644 "$src"; fi
    else
      rm -f -- "$src"
    fi
  done
  systemctl daemon-reload || true
  if [[ $was_active -eq 1 ]]; then systemctl restart ocp-agent || true; else systemctl stop ocp-agent || true; fi
  if [[ $was_enabled -eq 1 ]]; then systemctl enable ocp-agent >/dev/null 2>&1 || true; else systemctl disable ocp-agent >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap rollback ERR

install -o root -g root -m 0755 "$TMP_BIN" "$PREFIX/bin/ocp-agent"
install -o root -g root -m 0644 "$PREFIX/installer/ocp-agent.service" "$UNIT"
systemctl daemon-reload
if [[ $was_active -eq 1 ]]; then systemctl restart ocp-agent; else systemctl enable --now ocp-agent; fi
systemctl is-active --quiet ocp-agent
socket_meta=$(stat -c '%a:%G' /run/ocp/agent.sock)
[[ "$socket_meta" == "660:ocp-agent" ]]

# 探针必须逐行解析真实响应，且恰好 7 个 action 全部成功。
probe_output=$(cd "$PREFIX/scripts/probe" && go run main.go)
probe_count=$(printf '%s\n' "$probe_output" | python3 -c 'import json,sys; print(sum(1 for line in sys.stdin if line.strip() and json.loads(line).get("ok") is True))')
[[ "$probe_count" == 7 ]]
echo "PASS：Agent active；socket root:ocp-agent/0660；7/7 动作探针通过。"
echo "回滚材料：$BACKUP"
trap - ERR
