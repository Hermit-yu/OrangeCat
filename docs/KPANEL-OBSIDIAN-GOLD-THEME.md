# KPanel 曜石鎏金主题 — 设计系统素材（从演示站 panel.kejilion.pro 实测提取）

> 来源：https://panel.kejilion.pro/overview（演示站，简体中文，已切曜石鎏金主题）
> 提取方式：浏览器 Runtime 读取 :root 全部 CSS 变量 + 关键组件 computed style
> 用途：OrangeCatPanel 前端 UI 全量重写（视觉层复刻，功能逻辑保留）
> 注意：KPanel 为 AGPL-3.0-only，仅作设计原则/视觉参考，不复刻其代码/组件实现。

## 一、主题色板（THEME_COLOR_PRESETS 对应曜石鎏金）

- brand（主品牌色）：`#7c5818`（深金）
- brand-strong：`#513a10`（深棕金）
- brand-soft：`#ded9ce`（浅金灰）
- brand-muted：`#cbc0aa`（米金）
- theme-accent / sidebar-accent：`#a28227`（亮金）
- accent / primary / brand-action：`#7c5818`
- neutral（曜石基色）：`#12100e`（侧栏深色锚点）
- 壁纸 base：`linear-gradient(145deg, #b1aa9d, #dedbd6)`（米灰渐变）

## 二、完整 CSS 变量（:root 实测 158 项，核心节选）

### 背景/表面（浅色基调）
- `--bg: #e4e1dd`
- `--surface: #edece9`
- `--surface-subtle: #e9e7e3`
- `--surface-muted: #e9e7e3`
- `--surface-raised: #f0efed`
- `--surface-strong: #f0efed`
- `--surface-gradient: linear-gradient(180deg, #f0efed, #edece9)`
- `--surface-gradient-muted: linear-gradient(180deg, color-mix(in srgb, #e9e7e3 94%, #f0efed 6%), #e9e7e3)`
- `--page-ambient-background: linear-gradient(180deg, color-mix(in srgb, #e4e1dd 94%, #ded9ce 6%), #e4e1dd 38rem)`

### 文字
- `--text: #282520` / `--text-primary: #282520` / `--text-secondary: #4e473e`
- `--text-soft: #4e473e` / `--text-muted: #685f52` / `--text-tertiary: #685f52` / `--text-subtle: #685f52`
- `--muted: #685f52`
- `--on-brand: #ffffff` / `--on-danger: #ffffff`

### 边框/分割线
- `--border: #d7d6d3` / `--line: #d7d6d3` / `--line-soft: #d7d6d3` / `--border-subtle: #d7d6d3`
- `--border-strong: #c6c4c1` / `--control-border: #898682`

### 状态色
- `--success: #236e47` / `--success-soft: #d9dfd9`
- `--danger: #a13f49` / `--danger-soft: #e5dbd9` / `--danger-action: #a13f49`
- `--warning: #865814` / `--warning-soft: #e3ddd4` / `--amber: #865814` / `--amber-soft: #e3ddd4`
- `--blue: #315f95` / `--blue-soft: #dadee1`
- `--violet: #6655a4` / `--violet-soft: #e0dde2`
- `--neutral-soft: #e0dcd7`

### 品牌交互
- `--interaction-hover: color-mix(in srgb, #7c5818 8%, transparent)`
- `--interaction-hover-subtle: color-mix(in srgb, #7c5818 7%, #e9e7e3)`
- `--interaction-hover-surface: color-mix(in srgb, #7c5818 7%, #edece9)`
- `--interaction-pressed: color-mix(in srgb, #7c5818 13%, transparent)`

### 侧栏（浅色经典模式）
- `--sidebar-width: 252px` / `--sidebar-collapsed-width: 78px`
- `--sidebar: #12100e`（深色锚点，但经典模式实际用浅色）→ 实测 `#e9e7e3`
- `--sidebar-text: #f6f5f4` / `--sidebar-muted: #bcb5aa`
- `--sidebar-border: #292725` / `--sidebar-hover: #221b10` / `--sidebar-active: #302411` / `--sidebar-accent: #a28227`

### 阴影
- `--shadow-xs / --shadow-sm / --shadow-soft: 0 1px 2px rgb(18 16 14 / 7%)`
- `--shadow-md / --shadow: 0 1px 2px rgb(18 16 14 / 9%), 0 10px 28px rgb(18 16 14 / 11%)`
- `--shadow-feature: 0 2px 6px rgb(18 16 14 / 7%)`
- `--shadow-button: 0 1px 2px rgb(124 88 24 / 16%)`

### 圆角/布局
- `--radius-sm: 8px` / `--radius / --radius-md: 12px` / `--radius-lg: 18px`
- `--topbar-height: 70px` / `--sidebar-width: 252px`
- 字体：`Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif`
- `--font-mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace`

### 玻璃/材质（桌面模式，经典模式弱用）
- `--material-chrome-fill: rgb(240 239 237 / 96%)` / `--material-chrome-edge: rgb(40 37 32 / 18%)`
- `--material-panel-fill: rgb(240 239 237 / 96%)` / `--material-overlay-fill: rgb(240 239 237 / 96%)`
- `--desktop-glass: rgb(237 236 233 / 94%)` / `--desktop-glass-strong: rgb(240 239 237 / 96%)`

## 三、关键组件实测样式

### 侧栏（`.sidebar`）
- 背景 `#e9e7e3`（浅米灰）、宽 252px、右边框 `1px solid #d7d6d3`
- 品牌区 `padding: 0 62px 0 22px`
- 导航项 `.sidebar__link`：高 45px、padding 0 13px、圆角 12px、字号 14px、字重 500、颜色 `#282520`
- 激活项 `.sidebar__link.router-link-active`：背景 `#ded9ce`（浅金）、圆角 12px
- 底部用户 `.sidebar__user`：圆角 12px、边框 `1px solid #d7d6d3`、padding 9px

### 顶栏（`.topbar`）
- 背景 `color(srgb 0.928 0.924 0.912)` ≈ `#edece9`、高 70px、下边框 `1px solid #d7d6d3`、padding 0 38px
- `.topbar__title` 左、`.topbar__actions` 右（语言/桌面模式/主题/刷新）

### 主内容（`.page`）
- padding 38px、max-width 1640px、背景透明（继承 body 渐变）
- body 背景：`linear-gradient(color(srgb 0.893 0.880 0.863), #e4e1dd 608px)`（顶部暖米灰渐变）

### 卡片（`.panel-card` / `.metric-card`）
- 背景 `linear-gradient(#f0efed, #edece9)`、边框 `1px solid #d7d6d3`、圆角 12px、padding 20px（metric-card 18px）、阴影 `0 1px 2px rgb(18 16 14 / 7%)`
- 卡片头 `.panel-card__header`：字号 16px、字重 400、颜色 `#282520`
- `.metric-card__top`：字号 12px、字重 600、颜色 `#685f52`

### 按钮
- 主按钮 `.desktop-entry-button`：背景 `#ded9ce`、颜色 `#70511a`（深金）、圆角 8px、高 40px、padding 0 13px 0 10px、字重 600、字号 13px、边框 `1px solid #b1a185`、阴影 `0 2px 6px rgb(18 16 14 / 7%)`
- 图标按钮 `.icon-button`：高 34px、圆角 8px、边框 `1px solid #d7d6d3`、颜色 `#4e473e`

### 其他
- `.overview-system-card`：背景 `rgb(233 231 227 / 76%)`、圆角 12px、padding 14px、边框 `1px solid #d7d6d3`
- `.service-item`：背景 `#e9e7e3`、圆角 12px、padding 11px 12px、边框 `1px solid #d7d6d3`
- `.progress-track`：背景 `#e0dcd7`、圆角 999px、高 5px
- `.detail-list`：字号 16px、颜色 `#282520`

## 四、布局结构（复刻参考）

```
app-shell
├── sidebar (252px 浅色)
│   ├── sidebar__brand (品牌 mark + text + collapse 按钮)
│   ├── sidebar__nav (12 个 sidebar__link，激活 router-link-active)
│   └── sidebar__footer (Agent 在线 + 版本 + 用户 + 退出)
└── app-shell__main
    ├── topbar (70px: title + actions[语言/桌面/主题/刷新])
    └── page-content > page (38px padding, max-width 1640)
        ├── realtime-monitoring (metric-grid: metric-card×4)
        └── overview-grid (panel-card 多列)
```

## 五、复刻范围（OrangeCatPanel 现有功能映射）

登录页 / 概览 / 系统监控 / Docker / Nginx 站点 / 文件管理(P4) / 后台任务(P4-5) —— 全部换肤为曜石鎏金，功能逻辑（API 调用、审计、写操作）不动。
