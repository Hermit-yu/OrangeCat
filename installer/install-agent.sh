#!/usr/bin/env bash
# ocp-agent 安装器（R6：只新增 ocp-agent 服务，不碰任何存量服务）
set -euo pipefail

PREFIX=/opt/OrangeCatPanel
UNIT=/etc/systemd/system/ocp-agent.service

echo "[1/4] 编译 ocp-agent ..."
cd "$PREFIX"
go build -o "$PREFIX/bin/ocp-agent" ./agent/cmd/ocp-agent

echo "[2/4] 停掉裸跑的 ocp-agent（若有）..."
if pkill -x ocp-agent 2>/dev/null; then
  sleep 1
  echo "      已停止旧进程"
fi

echo "[3/4] 安装 systemd 单元 ..."
install -m 0644 "$PREFIX/installer/ocp-agent.service" "$UNIT"
systemctl daemon-reload

echo "[4/4] 启动并自检 ..."
systemctl enable --now ocp-agent
systemctl is-active ocp-agent && echo "      服务状态: active"

# 探针自检：7 个动作必须全部 ok:true
cd "$PREFIX/scripts/probe"
if go run main.go | grep -c '"ok":true' | grep -qx 7; then
  echo "PASS: 7/7 动作返回 ok:true，agent 安装完成"
else
  echo "FAIL: 探针自检未全绿，请查看 /var/log/ocp/agent-run.log" >&2
  exit 1
fi
