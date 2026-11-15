# OrangeCatPanel — 演示站全量 UI 复刻 + 真实功能绑定计划

> 2026-11-15 立。目标：把演示站 https://panel.kejilion.pro/ 的所有功能模块 + 子项 UI 全量做一遍，
> 且每个模块必须绑定真实功能（不空壳、不花架子、不编造）。
> 真源：docs/PROJECT-PLAN.md（P0-P15）+ agent 已注册 40 动作 + panel 已注册 API。

## 一、差距矩阵（演示站 16 页面 ↔ 我们现状）

| 演示站模块 | 我们现状 | 真实绑定能力 | 处理策略 |
|---|---|---|---|
| Overview 概览 | ✅ 已有（6 板块+真实数据） | system.info/metrics、docker、nginx、net | 已达标 |
| AI 助手 /ai | ✅ 完成 | **agnes API key 可用**（/etc/horizon/horizon.env，已跑通 agnes-3.0-flash） | **切片 A：✅ 完成**（fb4ae6e） |
| Sites /sites | ✅ 完成 | nginx.sites.full + nginx.test/reload | **切片 B：✅ 完成**（bddd715） |
| App marketplace /apps | ✅ 完成 | 无真实应用源（需 P11） | **✅ 完成**（d135a1b，标依赖未就绪不编造） |
| Docker /docker | ✅ 完成 | docker.* + compose.projects | **切片 C：✅ 完成**（4b60c68） |
| Virtual machines /vms | ✅ 完成 | **无 qemu/libvirt**（未安装） | **✅ 完成**（d135a1b，标依赖未就绪不编造） |
| Files /files | ✅ 已有（完整 P4） | fs.* | 已达标（补面包屑/权限细节） |
| Terminal /terminal | ✅ 已有（P5 PTY） | pty.* | 已达标（补多窗格/会话列表） |
| Diagnostics /diagnostics | ✅ 完成 | net.diagnostics + health.check | **切片 D：✅ 完成**（051d137） |
| Cluster /cluster | ✅ 完成 | 无多节点（需 P8） | **✅ 完成**（d135a1b，标依赖未就绪不编造） |
| Activity /activity | ✅ 完成 | authaudit 日志 + task.* | **切片 E：✅ 完成**（d039ae2） |
| Settings /settings | ✅ 完成 | 账户/外观/主机健康真实 | **切片 F：✅ 完成**（4a19002，改密码真实+其余标未就绪） |
| Process manager /processes | ✅ 完成 | process.kill + /proc 遍历 | **切片 G：✅ 完成**（9c74dcb，加 cpu_pct/state+汇总卡+搜索） |
| Monitoring /monitoring | ✅ 完成 | /api/history（raw+hourly） | **切片 H：✅ 完成**（c63760f，时间范围+多指标+汇总卡） |
| System /system | ✅ 完成 | system.info/metrics 真实；写操作 P6 | **切片 I：✅ 完成**（4a19002，只读真实+写操作标未就绪） |
| Audit /audit | ✅ 完成 | authaudit JSONL 真实 | 并入切片 E（d039ae2） |

## 二、分片执行顺序（每片=纵向可验收切片）

- **A. AI 助手**（真实 agnes 绑定）：会话/模型选择/发送/响应渲染。新增 agent action `ai.chat`（读 key 调 agnes 端点）+ panel API + 前端会话 UI。**✅ 完成**（fb4ae6e，2026-11-15）。
- **B. Sites 站点管理**：标签页（全部/健康/待审/仅配置）+ 站点详情卡。真实数据 nginx.sites.full。**✅ 完成**（bddd715，2026-11-15）。
- **C. Docker Compose**：compose 项目列表 + 状态 + 校验。**✅ 完成**（4b60c68，2026-11-15；compose 启动/停止 up/down 属 P2 遗留，路径白名单未定）。
- **D. Diagnostics 诊断工具**：8 工具 UI，每工具绑真实执行（net.diagnostics 等），benchmark 类标注"长时任务"。**✅ 完成**（051d137，2026-11-15）。
- **E. Activity/Audit 活动**：变更任务（task.*）+ 安全审计（authaudit 查询 API）。**✅ 完成**（d039ae2，2026-11-15）。
- **F. Settings 设置**：账户（改密码真实）+ 外观（本地存储持久化，真实）+ 主机健康（真实）。**✅ 完成**（4a19002，2026-11-15）。
- **G. Process 完整表**：全部进程 + 汇总卡 + 搜索 + 状态/CPU 列。真实 /proc 遍历。**✅ 完成**（9c74dcb，2026-11-15）。
- **H. Monitoring 历史**：时间范围（1h/6h/24h/7d/30d）+ 多指标。真实 /api/history。**✅ 完成**（c63760f，2026-11-15）。
- **I. System 系统中心**：真实只读（system.info/metrics）+ 写操作标依赖未就绪。**✅ 完成**（4a19002，2026-11-15）。
- **J. 未就绪模块**：应用市场（P11）/集群（P8）/虚拟机（无 qemu）——UI 完成且标"依赖未就绪"（不编造）。**✅ 完成**（d135a1b，2026-11-15）。

## 三、硬约束（沿用 PROJECT-PLAN 第 6 节"可用"定义）

1. 真实 API/Agent 动作，无静态模拟数据、无空实现。
2. API 字段来自真实数据源，前后端 shape 一致。
3. 功能页在认证浏览器真实渲染 + 交互已执行。
4. 写动作在独立测试目标执行 + 回读验证；不拿生产破坏性动作验证。
5. 无真实数据源的模块 UI 必须显示"依赖未就绪"，不得假成功。
6. 单根 Go 模块；测试从仓库根跑；index.html LF + 无内联 style/onclick + CSP nonce。
