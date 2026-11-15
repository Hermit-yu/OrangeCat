#!/usr/bin/env bash
# ocp-sampler 安装候选；默认只读检查，须显式 --apply 才会覆盖二进制/操作服务。
set -euo pipefail

PREFIX=/opt/OrangeCatPanel
SAMPLER_UNIT=/etc/systemd/system/ocp-sampler.service
BIN=$PREFIX/bin/ocp-sampler
MODE=${1:---check}
if [[ "$MODE" != "--check" && "$MODE" != "--apply" ]]; then
  echo "用法: $0 [--check|--apply]" >&2
  exit 2
fi
if [[ ! -f "$PREFIX/installer/ocp-sampler.service" || ! -f "$PREFIX/panel/cmd/ocp-sampler/main.go" ]]; then
  echo "采样器 unit 或源码不存在。" >&2
  exit 1
fi

TMP_BIN=$(mktemp "${TMPDIR:-/tmp}/ocp-sampler.XXXXXX")
cleanup() { rm -f -- "$TMP_BIN"; }
trap cleanup EXIT
echo "[1/3] 编译采样器候选 ..."
go -C "$PREFIX" build -o "$TMP_BIN" ./panel/cmd/ocp-sampler
"$TMP_BIN" --help >/dev/null 2>&1 || true
echo "候选 ocp-sampler 构建通过。"

if [[ "$MODE" == "--check" ]]; then
  echo "只读检查完成；未覆盖二进制、未操作服务。"
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  echo "--apply 必须以 root 运行。" >&2
  exit 1
fi
if ! systemctl is-active --quiet ocp-agent; then
  echo "ocp-agent 不 active；采样器依赖 Agent socket，先安装 Agent。" >&2
  exit 1
fi
socket_meta=$(stat -c '%a:%G' /run/ocp/agent.sock 2>/dev/null || true)
if [[ "$socket_meta" != "660:ocp-agent" ]]; then
  echo "Agent socket 权限未就绪（当前 ${socket_meta:-不可见}）。" >&2
  exit 1
fi
if [[ -L "$SAMPLER_UNIT" || -L "$BIN" ]]; then
  echo "unit 或二进制为符号链接；拒绝覆盖。" >&2
  exit 1
fi

getent group ocp-agent >/dev/null || groupadd --system ocp-agent
getent group ocp-panel >/dev/null || groupadd --system ocp-panel
getent passwd ocp-panel >/dev/null || useradd --system --gid ocp-panel --home-dir /nonexistent --shell /usr/sbin/nologin ocp-panel
install -d -o ocp-panel -g ocp-panel -m 0700 /var/lib/ocp
# 历史教训：以 root 探测/连库会建出 root 拥有的 DB 文件，非 root 采样器随后只能读到只读库。
# 若现有 DB 不属于 ocp-panel，先移走备份（保留旧数据）再让服务自己重建。
for suf in "" -wal -shm; do
  dbf=/var/lib/ocp/metrics.db$suf
  if [[ -f "$dbf" ]] && [[ $(stat -c '%U' "$dbf") != "ocp-panel" ]]; then
    mv -- "$dbf" "${dbf}.stray-$(date -u +%Y%m%dT%H%M%SZ)"
    echo "已移走非 ocp-panel 拥有的 $dbf"
  fi
done

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/var/backups/ocp-sampler/pre-update-$STAMP
install -d -o root -g root -m 0700 "$BACKUP"
for src in "$BIN" "$SAMPLER_UNIT"; do
  name=$(basename "$src")
  if [[ -e "$src" ]]; then cp -a -- "$src" "$BACKUP/$name"; printf 'present\n' >"$BACKUP/$name.state"; else printf 'absent\n' >"$BACKUP/$name.state"; fi
done
was_active=0; systemctl is-active --quiet ocp-sampler && was_active=1 || true
was_enabled=0; systemctl is-enabled --quiet ocp-sampler && was_enabled=1 || true
rollback() {
  status=$?
  if [[ $status -eq 0 ]]; then return; fi
  trap - ERR
  echo "采样器更新失败；恢复原二进制和 unit。" >&2
  for pair in "$BIN:ocp-sampler" "$SAMPLER_UNIT:ocp-sampler.service"; do
    src=${pair%%:*}; name=${pair#*:}
    if [[ -f "$BACKUP/$name.state" ]] && [[ $(<"$BACKUP/$name.state") == present ]]; then
      install -D -m 0600 "$BACKUP/$name" "$src"
      if [[ "$src" == "$BIN" ]]; then chmod 0755 "$src"; else chmod 0644 "$src"; fi
    else
      rm -f -- "$src"
    fi
  done
  systemctl daemon-reload || true
  if [[ $was_active -eq 1 ]]; then systemctl restart ocp-sampler || true; else systemctl stop ocp-sampler || true; fi
  if [[ $was_enabled -eq 1 ]]; then systemctl enable ocp-sampler >/dev/null 2>&1 || true; else systemctl disable ocp-sampler >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap rollback ERR

install -o root -g root -m 0755 "$TMP_BIN" "$BIN"
install -o root -g root -m 0644 "$PREFIX/installer/ocp-sampler.service" "$SAMPLER_UNIT"
systemctl daemon-reload
if [[ $was_active -eq 1 ]]; then systemctl restart ocp-sampler; else systemctl enable --now ocp-sampler; fi
systemctl is-active --quiet ocp-sampler
sleep 3
# 真实验收：DB 必须由 ocp-sampler 自己创建并拥有。
# 注意：安装器不能以 root 预先连库（会以 root 建出 DB 文件，导致非 root 采样器只读失败）。
db=/var/lib/ocp/metrics.db
[[ -f "$db" ]]
db_meta=$(stat -c '%U:%G' "$db")
[[ "$db_meta" == "ocp-panel:ocp-panel" ]]
echo "PASS：ocp-sampler active；$db 由 ocp-panel 创建（$db_meta）。"
echo "回滚材料：$BACKUP"
trap - ERR