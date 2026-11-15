#!/usr/bin/env bash
# OrangeCatPanel non-root panel installer. Default mode is non-mutating --check.
set -euo pipefail

PREFIX=/opt/OrangeCatPanel
PANEL_UNIT=/etc/systemd/system/ocp-panel.service
PROXY_DIR=/etc/ocp-panel
PROXY_FILE=$PROXY_DIR/trusted-proxy-ips
PASSWORD_FILE=/var/lib/ocp/panel-password
MODE=${1:---check}

if [[ "$MODE" != "--check" && "$MODE" != "--apply" ]]; then
  echo "用法: OCP_TRUSTED_PROXY_IPS='精确IP[,精确IP...]' $0 [--check|--apply]" >&2
  exit 2
fi
if [[ -z "${OCP_TRUSTED_PROXY_IPS:-}" ]]; then
  echo "缺少 OCP_TRUSTED_PROXY_IPS；需提供反向代理的精确 IP，不能填网段。" >&2
  exit 2
fi

NORMALIZED_PROXY_FILE=$(mktemp "${TMPDIR:-/tmp}/ocp-proxies.XXXXXX")
BUILD_FILE=$(mktemp "${TMPDIR:-/tmp}/ocp-panel.XXXXXX")
cleanup() { rm -f -- "$NORMALIZED_PROXY_FILE" "$BUILD_FILE"; }
trap cleanup EXIT
python3 - "$OCP_TRUSTED_PROXY_IPS" "$NORMALIZED_PROXY_FILE" <<'PY'
import ipaddress, pathlib, sys
raw, path = sys.argv[1:]
items = [part.strip() for part in raw.split(',')]
if not items or any(not item for item in items):
    raise SystemExit('可信代理列表有空项')
ips = []
for item in items:
    try:
        ip = ipaddress.ip_address(item)
    except ValueError:
        raise SystemExit(f'不是精确 IP 地址：{item!r}')
    text = str(ip)
    if text not in ips:
        ips.append(text)
pathlib.Path(path).write_text(''.join(ip + '\n' for ip in ips), encoding='ascii')
PY

if [[ ! -f "$PREFIX/installer/ocp-panel.service" || ! -f "$PREFIX/panel/cmd/ocp-panel/main.go" ]]; then
  echo "项目源码或 Panel unit 不完整。" >&2
  exit 1
fi
go -C "$PREFIX" build -o "$BUILD_FILE" ./panel/cmd/ocp-panel
printf '候选 Panel 构建通过；可信代理 IP 条目数：'
python3 - "$NORMALIZED_PROXY_FILE" <<'PY'
import pathlib, sys
print(len(pathlib.Path(sys.argv[1]).read_text().splitlines()))
PY

if [[ "$MODE" == "--check" ]]; then
  echo "只读检查完成；未创建用户/组、未改文件、未操作服务。"
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  echo "--apply 必须以 root 运行。" >&2
  exit 1
fi
if ! systemctl is-active --quiet ocp-agent; then
  echo "ocp-agent 当前不 active；先安装并启动 Agent，Panel 安装未开始。" >&2
  exit 1
fi
if [[ -L "$PROXY_FILE" || -L "$PANEL_UNIT" || -L "$PREFIX/bin/ocp-panel" ]]; then
  echo "检测到 unit、二进制或可信代理配置为符号链接；拒绝覆盖。" >&2
  exit 1
fi
socket_meta=$(stat -c '%a:%G' /run/ocp/agent.sock 2>/dev/null || true)
if [[ "$socket_meta" != "660:ocp-agent" ]]; then
  echo "Agent socket 权限尚未就绪（当前 ${socket_meta:-不可见}）；先安装新 Agent unit 并确认 root:ocp-agent、0660。" >&2
  exit 1
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_ROOT=/var/backups/ocp-panel
BACKUP=$BACKUP_ROOT/pre-nonroot-$STAMP
install -d -o root -g root -m 0700 "$BACKUP"
for src in "$PREFIX/bin/ocp-panel" "$PANEL_UNIT" "$PROXY_FILE"; do
  name=$(basename "$src")
  if [[ -e "$src" ]]; then
    cp -a -- "$src" "$BACKUP/$name"
    printf 'present\n' >"$BACKUP/$name.state"
  else
    printf 'absent\n' >"$BACKUP/$name.state"
  fi
done
if [[ -e "$PASSWORD_FILE" ]]; then
  if [[ ! -f "$PASSWORD_FILE" || -L "$PASSWORD_FILE" ]]; then
    echo "管理员密码路径不是普通文件；停止，未修改密码文件。" >&2
    exit 1
  fi
  stat -c '%u:%g %a' "$PASSWORD_FILE" >"$BACKUP/password-file.meta"
else
  printf 'absent\n' >"$BACKUP/password-file.meta"
fi
stat -c '%u:%g %a' /var/lib/ocp 2>/dev/null >"$BACKUP/password-dir.meta" || printf 'absent\n' >"$BACKUP/password-dir.meta"
was_active=0; systemctl is-active --quiet ocp-panel && was_active=1 || true
was_enabled=0; systemctl is-enabled --quiet ocp-panel && was_enabled=1 || true

rollback() {
  status=$?
  if [[ $status -eq 0 ]]; then return; fi
  trap - ERR
  echo "安装失败，恢复二进制/unit/代理配置和 Panel 原运行状态。" >&2
  for pair in "$PREFIX/bin/ocp-panel:ocp-panel" "$PANEL_UNIT:ocp-panel.service" "$PROXY_FILE:trusted-proxy-ips"; do
    src=${pair%%:*}; name=${pair#*:}
    if [[ -f "$BACKUP/$name.state" ]] && [[ $(<"$BACKUP/$name.state") == present ]]; then
      install -D -m 0600 "$BACKUP/$name" "$src"
      if [[ "$src" == "$PREFIX/bin/ocp-panel" ]]; then chmod 0755 "$src"; fi
      if [[ "$src" == "$PANEL_UNIT" ]]; then chmod 0644 "$src"; fi
      if [[ "$src" == "$PROXY_FILE" ]]; then chown root:ocp-panel "$src"; chmod 0640 "$src"; fi
    else
      rm -f -- "$src"
    fi
  done
  if [[ -f "$BACKUP/password-file.meta" ]] && [[ $(<"$BACKUP/password-file.meta") == absent ]]; then
    rm -f -- "$PASSWORD_FILE"
  elif [[ -f "$BACKUP/password-file.meta" ]]; then
    read -r owner mode <"$BACKUP/password-file.meta"
    chown "$owner" "$PASSWORD_FILE"; chmod "$mode" "$PASSWORD_FILE"
  fi
  if [[ -f "$BACKUP/password-dir.meta" ]] && [[ $(<"$BACKUP/password-dir.meta") != absent ]]; then
    read -r owner mode <"$BACKUP/password-dir.meta"
    chown "$owner" /var/lib/ocp; chmod "$mode" /var/lib/ocp
  else
    rmdir /var/lib/ocp 2>/dev/null || true
  fi
  systemctl daemon-reload || true
  if [[ $was_active -eq 1 ]]; then systemctl restart ocp-panel || true; else systemctl stop ocp-panel || true; fi
  if [[ $was_enabled -eq 1 ]]; then systemctl enable ocp-panel >/dev/null 2>&1 || true; else systemctl disable ocp-panel >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap rollback ERR

getent group ocp-agent >/dev/null || groupadd --system ocp-agent
getent group ocp-panel >/dev/null || groupadd --system ocp-panel
getent passwd ocp-panel >/dev/null || useradd --system --gid ocp-panel --home-dir /nonexistent --shell /usr/sbin/nologin ocp-panel
install -d -o root -g ocp-panel -m 0750 "$PROXY_DIR"
install -o root -g ocp-panel -m 0640 "$NORMALIZED_PROXY_FILE" "$PROXY_FILE"
install -d -o ocp-panel -g ocp-panel -m 0700 /var/lib/ocp
if [[ -e "$PASSWORD_FILE" ]]; then chown ocp-panel:ocp-panel "$PASSWORD_FILE"; chmod 0600 "$PASSWORD_FILE"; fi
install -o root -g root -m 0755 "$BUILD_FILE" "$PREFIX/bin/ocp-panel"
install -o root -g root -m 0644 "$PREFIX/installer/ocp-panel.service" "$PANEL_UNIT"
systemctl daemon-reload
if [[ $was_active -eq 1 ]]; then systemctl restart ocp-panel; else systemctl enable --now ocp-panel; fi
systemctl is-active --quiet ocp-panel
# 就绪等待：restart 后端口可能尚未接受连接，最多重试 15 次（每次 1s），避免误判失败触发回滚。
status=""
for _ in $(seq 1 15); do
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' http://172.18.0.1:8390/api/login 2>/dev/null || true)
  if [[ "$status" == 405 ]]; then break; fi
  sleep 1
done
[[ "$status" == 405 ]]
echo "Panel 已启动；GET 登录端点返回 405，绑定地址/反代/登录验证仍需单独验收。"
echo "回滚材料：$BACKUP"
trap - ERR
