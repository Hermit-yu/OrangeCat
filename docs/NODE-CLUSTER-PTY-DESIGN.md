# 受控终端默认连本机 + 集群哪吒对接方案

> 决策记录（2026-11-15，哥哥拍板）：受控终端**默认连接本机**（panel 直连本机 agent 开 PTY）；将来有集群时，**按哪吒监控（Nezha）的 Agent 对接方案**扩展——一个面板管理多节点 Agent，按目标节点路由终端/文件/任务请求。

## 一、当前实现（默认连本机）

架构：`浏览器 → panel(HTTPS) → agentbridge(本机 unix socket) → 本机 agent → PTY`

- **panel** 持有**单个** `agentbridge.Client`（`main.go:81` `p.clients = agentbridge.New(*sock)`），直连本机 agent。
- **agent**（`agent/internal/actions/pty.go`）是 PTY 的实际执行者：`pty.open/status/input/close` 四个动作，`/bin/bash` 白名单，root 下受控 PTY。
- `pty.open` 参数：`command`、`rows`、`cols`（无 host/agent_id）——天然**默认本机**。

### 预留扩展点（已实现，2026-11-15）
- panel `handlePTYOpen` 接受可选 `agent_id` 字段（`api_pty.go`）。
- **当前为单机部署**：`agent_id` 为空或 `local`/`local-agent` → 走本机 agent；其他值 → 明确返回
  `集群未就绪：当前为单机部署，仅本机终端可用（agent_id 仅支持 local）`，并落审计。
- **不编造多节点支持**：没有多 agent 连接池前，绝不静默忽略 agent_id 或假装已连接。

## 二、将来集群对接方案（哪吒监控 V2 架构）

哪吒方案（`https://nezha.wiki/guide/architecture.html`）：**一个 Dashboard 管理多个 Agent**。

```
浏览器 / API ──HTTPS/WS──▶ Dashboard ──gRPC──▶ Agent(节点1)
                                                Agent(节点2)
                                                Agent(节点N)
```

- **Dashboard**：控制面 + 展示入口。验证用户/Token/Agent 身份；接收 Agent 上报；维护服务器/分组/用户/任务；**把终端/文件/任务/NAT 授权请求转交到目标 Agent**。
- **Agent**：每台被监控节点一个。用 `client_secret` + `uuid` 接入 Dashboard；上报主机状态；执行被分配的 HTTP/Ping/TCP 检查；在授权后执行终端/文件/任务。`disable_command_execute` 可关闭远程执行。
- **远程操作路由**：Dashboard 验证调用者权限后，通过 Agent 的**任务或 IOStream 通道**转发到目标 Agent（按服务器 UUID 识别）。
- **并发配额**：单用户最多 20 条在线终端+文件 IOStream；单目标服务器最多 40 条 IOStream。

### 映射到 OrangeCatPanel
| 哪吒组件 | OrangeCatPanel 对应 |
|---|---|
| Dashboard | `panel`（加多 agent 连接池 `map[agent_id]*agentbridge.Client`） |
| Agent | `agent`（每节点部署一个；接入用 client_secret + uuid） |
| 远程操作路由 | `pty.open/status/input/close` 按 `agent_id` 路由到对应连接池条目 |
| 身份接入 | 哪吒：gRPC + `NZ_CLIENT_SECRET`/`NZ_UUID`；我们：unix socket / 后续可加 TLS+gRPC |
| 并发配额 | 哪吒：单用户 20 / 单服务器 40 IOStream；我们：沿用 `ptyMaxSessions=4`，集群时按节点配额 |
| 关闭远程执行 | 哪吒：`disable_command_execute`；我们：沿用 `OCP_AGENT_PTY_ENABLED`（默认关） |

### 实施要点（有集群时）
1. panel 侧把 `p.clients` 从单连接改为 `map[string]*agentbridge.Client`（key = agent_id/uuid），默认 `local` = 本机。
2. `handlePTYOpen` 按 `agent_id` 选连接；未知 agent_id → 404 明确报错。
3. 每节点 agent 启动时注册自身 uuid + client_secret（哪吒式接入），panel 侧维护在线节点列表（可复用 `/api/health` 或新增 `cluster.nodes`）。
4. 前端终端页加**节点选择器**（默认本机）；未选节点=本机，与当前一致。
5. 安全基线不变：PTY 默认关闭、命令白名单、逐次审计、并发配额。

## 三、验收
- 本机：`agent_id` 空 → 正常开终端（已验）；`agent_id: "node-x"` → `集群未就绪` 明确报错（不编造）。
- 全量 `go test` 绿 + `check.sh` 8/8。
