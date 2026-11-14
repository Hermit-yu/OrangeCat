# OrangeCatPanel 计划、执行准则与认证切片复核清单

- 日期：2026-11-14
- 仓库基线：`b128c0c990a4624d4e659fe9348c1b1e73d7cb80`（当前改动未提交）
- 参考基线：KPanel `e82c1a5dea2ac224450d054e886c13626c43d35e`，本地 `origin/main` 与审阅 HEAD 一致
- 范围：计划书 v1.4、项目执行准则、统一本地门禁、登录 JSON 输入限制、CSRF/Origin 注销及窗口限速/可信反代 IP 切片

## 逐条验收

1. 总计划覆盖 KPanel README 公开功能族：本机与系统监控、网络/硬件检查、Docker/Compose/更新/备份迁移、网站/负载均衡/跳转、网站访问与安全事件分析、文件/终端、应用目录、通知、公开分享、多节点/批量与节点间传输、AI 安全自动审批、多语言、经典/桌面双模式、主题/3D 场景、可选隔离浏览器、兼容适配与分发。
2. 计划区分能力目标和实际实现状态，不把路线图、静态 UI 或构建结果算作完成。
3. AGPL-3.0-only 来源边界明确：只借鉴能力类别，不复制代码、协议实现、文案、视觉稿、图片/图标或品牌；兼容适配须有公开/授权契约及许可审查。
4. `RULES.md`、`docs/PROJECT-PLAN.md`、`docs/EXECUTION-STANDARDS.md` 职责分层清楚，互相引用且不冲突。
5. 执行准则包含开工契约、风险分级、TDD、真实数据/浏览器/主机验收、权限、失败恢复、Git 脏工作树保护、部署与回滚门禁、四态证据口径。
6. `scripts/check.sh` 可运行，含 Go 全量测试、vet、Panel/Agent build、嵌入 JS 语法、前端请求行为测试、空白差异检查；不部署、不重启、不写系统配置。
7. 登录入口拒绝畸形 JSON、未知字段、尾随 JSON、超长请求及缺少凭据；尾随超限空白也返回 413。
8. 登录创建高强度随机服务端 session 和独立 CSRF token；session cookie 为 Secure/HttpOnly，CSRF cookie 为 Secure/SameSite=Strict 并供同源 JS 读取。
9. 注销仅接受 POST；跨站 Origin、scheme/host/port 不匹配、缺少/不匹配 CSRF token 均被拒；正确 token 成功撤销 session 并清理 cookies。
10. 前端对非登录 POST 从 CSRF cookie 复制自定义请求头；登录不依赖先有 token；缺 token 时不捏造值；失败时显示可重试状态。
11. Go Handler 测试、Node 前端请求测试、`bash scripts/check.sh` 与 `go test -race ./...` 结果通过；文档内部链接与 Markdown 表格列数检查通过。
12. 线上 `ocp-agent`、`ocp-panel` 当前 active/enabled；systemd 记录它们分别于 07:10:28、07:11:15 重启。Agent 运行 binary、磁盘文件和当前源码重编结果 hash 均为 `b391908bf7a6a932023f2d3a92da8a1324c47a9c13d625192d96067846162d83`；Panel 运行 binary 与 `bin/ocp-panel` hash 均为 `fbfa6a701fe313fec5224b46ea1ab23fe2fcd5a22a56639fa1a7ccac990ae9a9`，且不含 `ocp_csrf`/`X-CSRF-Token`/`trusted-proxy-ips`/“磁盘数据暂不可用”标记。结论：Agent 磁盘修复版本已运行；Panel 当前认证改动未部署。未清理现存工作树改动。
13. 仍未完成的 P0/P1–P15 功能明确列为未实现或未实机验证，不作全量交付声明。
14. 盲审发现的永久 429 已在候选修复为真实 15 分钟窗口；可控时钟测试证明超窗后正确密码登录恢复，4097 个来源测试证明跟踪表不超过 4096 条。
15. 反代真实来源不能直接信任用户头：仅精确配置的代理 peer IP 可提供 `X-Real-IP`；未信任来源伪造头会被忽略。生产 systemd 当前尚未设置 `--trusted-proxy-ips`，候选尚未部署。
16. 会话表已在候选中补统一过期/容量清理（12h TTL、4096 上限、查询回收、满则淘汰最旧，重启失效）；另有统一安全响应头 + nonce CSP、认证审计、Agent Socket 边界与安装器候选。仍未真实浏览器/反代链路验收，因此仍不批准部署。

## 验收证据

- 全量本地门禁与 race 输出：`/root/.hermes/cache/scratch/orangecat-final-gate-20261114.log`
- 失败先行记录：登录超限尾随空白测试首次返回 400（预期 413），修复后全量门禁通过。
- 服务状态：`systemctl is-active/is-enabled` 分别返回两服务均 `active`/`enabled`；Agent 的当前运行文件与源码重编 SHA 均为 `b391908bf7a6a932023f2d3a92da8a1324c47a9c13d625192d96067846162d83`；Panel 的运行进程从 07:11:15 起运行 SHA-256 `fbfa6a701fe313fec5224b46ea1ab23fe2fcd5a22a56639fa1a7ccac990ae9a9` 的旧二进制，Go build info revision 为 `b128c0c990a4624d4e659fe9348c1b1e73d7cb80`。本轮最终校验期间未操作服务。
- 真实浏览器/候选部署：未执行；本地认证改动保持“已实现未实机验证”。此前 systemd 重启记录如上，不把它混称为本候选发布。

## 生产部署记录（2026-11-14 11:02–11:15，用户明示授权）

- 部署方式：`installer/install-agent.sh --apply` + `OCP_TRUSTED_PROXY_IPS=172.18.0.6 installer/install-panel.sh --apply`；Agent 备份 `/var/backups/ocp-agent/pre-update-20261114T030219Z`，Panel 备份 `/var/backups/ocp-panel/pre-nonroot-20261114T030235Z`。
- 部署缺陷与修复：首轮 `install-panel.sh` 用 `enable --now`（对已 active 服务不重启），导致 Panel 进程持旧二进制 deleted inode 运行；已修补为“已 active 则 restart，否则 enable --now”，并 `systemctl restart ocp-panel` 使候选生效。
- 版本核实：`/proc/<MainPID>/exe` SHA = `bin/ocp-panel` = `fef96631a3346d75a01aed373e112617093fc1e0c274cd876b36984f12caa9fc`；Agent 运行 SHA = `a5c64c7d6295c32e9978e88638eeedfe2fd48646a626ee15ad30d6f424b8003d`。Panel 以 uid/gid ocp-panel 运行，Groups 含 ocp-agent；`/var/log/ocp-panel` 0700；`/etc/ocp-panel/trusted-proxy-ips` 0640 root:ocp-panel 内容仅 172.18.0.6；socket 660 root:ocp-agent。
- Canary（经 https://hermes.taoque.top/orangecat/）：根 200、login GET 405、overview 未认证 401、错密码 401、CSP/nonce 与安全头透传、主站 302 正常；认证审计落盘 1 条 `bad_credentials`、`client_ip=38.14.254.100`（真实出口，非代理地址）、无明码。
- 未做：认证浏览器逐视图渲染验收（由哥哥执行）；git 提交/推送未做。

## 复核结果与限制

- 双模型裁判：`judge.py` 运行 3 次后仍返回无正文，`/root/.hermes/dual-review/verdict-20261114-081032.json` 的 `machine` 为 `null`；按双模型复核规程停止重试，裁判未参与。
- 自审：计划、执行准则、认证实现与门禁逐项核对；先发现永久 429 与反代来源共享桶，均在候选中修复并增加测试。该人工自审不能替代独立复核；上线签核仍须独立复核并完成剩余 P0。

## 影子实例真机验证（2026-11-14 10:46–10:49，本人与子代理各自独立执行）

- 环境：`/tmp/ocp-verify/` 下由当前源码新编译的 `ocp-agent` + `ocp-panel`，监听 `127.0.0.1:8392`，临时密码文件 `/tmp/ocp-verify/panel-pass`（0600，故意带尾随换行以验证修复），`-trusted-proxy-ips` 留空。生产 `ocp-agent`/`ocp-panel`（PID 1357686/1359056，172.18.0.1:8390）全程未动。
- 控制面实测：错密码→401；对密码（尾随换行文件）→200 + `ocp_session`/`ocp_csrf`；未认证访问 `/api/overview`→401；注销无/错 CSRF 头→403（审计 `csrf_failed`），正确头→200，注销后再访问→401。
- 数据链路实测：`/api/overview` 返回真实主机（hostname=taoque，kernel=6.8.0-147-generic，Ubuntu 24.04.1 LTS，8 核，内存 7939 MiB，磁盘 48/34 GiB/72%，load 0.27/0.29/0.34）；`/api/nginx` 8 个站点含证书路径；`/api/processes`、`/api/net`（含 br-*/docker0/ens17 及 rx/tx/speed）、`/api/docker`（12 容器/24 镜像/11 卷）均为活主机数据，无静态 fixture。
- 审计实测：认证审计 5 条，reason 集合 `{bad_credentials, credentials_accepted, csrf_failed, logout_completed}`，不含明文密码；Agent 审计 `params:null`，不落请求参数。
- 发现并修复：密码文件按原文读取，尾随换行导致 401；已改为 `strings.TrimRight(...,"\r\n")`，新增 `TestReadPasswordFileTrimsTrailingLineEndings`（先红后绿），门禁与 race 重跑全绿。
- 限制：此为 API 级真机验证；认证浏览器渲染与反代链路（nginx→172.18.0.6→panel）仍未做，状态保持“已实现未实机验证”。
- 上线结论：不批准部署；会话表、安全响应头 + nonce CSP、认证审计、Agent Socket 边界与安装器候选均已在本地候选实现并过自动化门禁；生产 nginx 容器真实 IP 已核实为 `172.18.0.6`，但 systemd 未配置 `--trusted-proxy-ips` / `--trusted-proxy-file /etc/ocp-panel/trusted-proxy-ips`，候选未部署。
