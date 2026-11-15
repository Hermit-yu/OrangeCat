#!/usr/bin/env bash
# OrangeCatPanel — uninstall. Backs up runtime state, stops services, removes
# ONLY OrangeCatPanel-owned files. Never touches nginx/SSH/ufw/certs/sites.
# Usage: installer/uninstall.sh [--yes]
set -euo pipefail

PREFIX=/opt/OrangeCatPanel
BACKUP_ROOT=/var/backups/ocp-panel-uninstall
UNITS=(ocp-panel.service ocp-agent.service ocp-sampler.service)
OCP_FILES=(
  "$PREFIX"
  /etc/systemd/system/ocp-panel.service
  /etc/systemd/system/ocp-agent.service
  /etc/systemd/system/ocp-sampler.service
  /etc/ocp-panel
  /var/lib/ocp
  /var/log/ocp-panel
  /var/log/ocp-agent
)

[[ "${1:-}" == "--yes" ]] || { echo "卸载是破坏性操作；用 --yes 确认。" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "必须 root 运行。" >&2; exit 1; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$BACKUP_ROOT/pre-uninstall-$TS"
mkdir -p "$BACKUP"
echo "备份运行时状态 → $BACKUP"
for d in /var/lib/ocp /var/log/ocp-panel /var/log/ocp-agent /etc/ocp-panel; do
  if [[ -e "$d" ]]; then cp -a "$d" "$BACKUP/$(basename "$d")" 2>/dev/null || true; fi
done

echo "停止服务"
for u in "${UNITS[@]}"; do
  if systemctl list-unit-files 2>/dev/null | grep -q "$u"; then
    systemctl stop "$u" 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u"
  fi
done
systemctl daemon-reload

echo "删除 OCP 文件（不动 nginx/SSH/ufw/证书/站点）"
for f in "${OCP_FILES[@]}"; do
  [[ -e "$f" ]] && rm -rf "$f" && echo "  已删除 $f"
done

echo "卸载完成。备份保留在 $BACKUP（如需回滚，从该目录恢复并重新安装）。"
