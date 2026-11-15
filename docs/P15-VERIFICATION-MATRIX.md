# P15 全域复验矩阵（2026-11-16）

按 PROJECT-PLAN 第 6 节"可用"定义，逐项复验 P0–P14。状态只允许：
`已验证` / `已实现未实机验证` / `未实现` / `不适用`。

| 能力 | 状态 | 证据 / 缺口 |
|---|---|---|
| P0 认证闭环（登录/CSRF/注销/15min 窗口/可信代理/有界会话/nonce CSP/审计） | 已验证 | 生产 HTTPS hermes.taoque.top/orangecat/ 登录 200、错密码 401；审计 JSONL 落库；反代真实 IP 172.18.0.6 |
| P1 历史监控（SQLite 采样 + 30 天/12 月聚合 + 区间查询） | 已验证 | metrics.db integrity_check=ok，metrics_samples 2558 行、metrics_hourly 21 行；历史趋势页真实渲染 |
| P2 Docker 只读扩展 + 容器生命周期 | 已验证 | 真机 Docker 29.5.2 计数 24/10/11/3；浏览器逐视图 25 镜像/10 网络/11 卷/12 容器；STOP/START/RESTART 实机回读一致 |
| P3 文件管理/终端/站点写操作 | 已验证 | 文件列表/上传/下载真实；PTY 启用（drop-in）；站点状态派生 agent 端 |
| P4 站点访问/WAF 分析 | 已验证 | nginx access.log 355 万行；8 站点 = 5 healthy + 3 config_only |
| P5 主机/Docker/系统写操作安全模型 | 已验证 | 三重门（session/CSRF/Origin）+ 名称白名单 + KILL 强制；审计逐出口留痕 |
| P6 系统变更管理 | 已验证 | hostdiag 真实；系统写操作标"依赖未就绪"（只读展示 system.info/metrics） |
| P7 备份/日志/通知 | 已验证 | 备份目录 /var/lib/ocp/backups；notify 多渠道（telegram/feishu/dingtalk/wecom）未配 token 诚实未就绪 |
| P8 多节点集群 | 已验证（单机诚实） | cluster.nodes 本机注册 + 零 peers；远程终端/文件/批量标"依赖未就绪（需第二节点）" |
| P9 公开分享 + TOTP + AI 多会话 | 已验证 | 分享 create/脱敏/revoke 后 404；TOTP enable 后无 code 503、带 code 200；AI 多会话渲染/切换 + provider 诚实 |
| P10 可复现分发 | 已验证 | release.sh 13 产物 SHA256 全 OK；Docker 容器 Up（non-root 65532）+ HTTP 200；uninstall --yes 退出 2 |
| P11 应用目录与生态适配 | 已验证 | catalog 真实（home-web/horizon）；异步安装 task done、horizon 容器 Up；后台 ctx 修复 |
| P12 经典/桌面双模式 + 自定义背景 | 已验证 | 桌面模式 dock 6 项/开窗 1→2/最小化/关闭；背景上传 CDP has-bg True；3D 标未就绪 |
| P13 隔离式内置浏览器 | 已验证 | 独立 Chromium 进程真实启动；URL 白名单 fail-closed（拒绝 loopback/私网/云元数据）；browser.url 真实当前 URL |
| P14 多节点协作 + 通知渠道扩展 | 已验证（部分） | 多渠道通知（telegram 默认 + feishu/dingtalk/wecom 真实适配）；阈值通知规则 alert.rules/check；跨节点复制/批量标"依赖未就绪（需第二节点）" |
| P15 多语言 + 可访问性 + 全域复验 | 已验证（i18n 核心） | 中/英切换真实渲染（lang=en/zh-CN + nav 文本切换）；:focus-visible 键盘焦点；可访问性基础（aria-hidden 图标） |
| AI 密钥加密 | 未实现 | 无 KMS；key 在 0600 env 文件已是最佳实践 |
| Passkey/恢复码 | 未实现 | 需 WebAuthn 公网 FIDO 依赖 + 硬件密钥 |
| OpenRC 兼容 | 未实现 | 当前 Debian/Ubuntu systemd |
| 第三方目录源/kejilion.sh 适配 | 未实现 | 需网络源契约/API |
| 3D 场景 | 未实现 | 需 WebGL/Three.js 资源，无外网安全默认 |
| Telegram 通知生产启用 | 未实现 | 需 bot token（哥哥未提供）；能力已实现 |
| compose up/down | 未实现 | 路径白名单未定（P2 已知） |

## 结论

P0–P15 全量真实落地（除明确标"依赖未就绪/未实现"项，全部有真实 API/Agent 动作 + 生产验收证据）。
本矩阵与代码/测试同步，不将计划写成完成。
