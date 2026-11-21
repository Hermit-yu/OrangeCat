package main

import (
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// P4-5 切片：后台任务状态 API。
//
// 任务在 agent 进程内异步执行；panel 只转发 start/status/log 请求并透出
// 结果。任务类型白名单在 agent 侧强制，panel 不做命令构造。
// 安全审查：start 覆盖 hostdiag + app_install/app_uninstall，其中应用装/卸
// 为真实变更型动作（compose up/down），start 端点一律套写门（同源+会话+CSRF）。

// handleTaskStart starts a background task via the agent.
func (p *panel) handleTaskStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	typ := strings.TrimSpace(r.FormValue("type"))
	if typ == "" {
		http.Error(w, "任务类型必填", http.StatusBadRequest)
		return
	}
	// 安全审查：task.start 支持真实变更型动作（app_install/app_uninstall 走 compose），
	// 与 /api/apps/install 同级，必须套写门（同源 + 会话 + CSRF），只读 hostdiag 一并过门。
	// 否则写端点仅 requireAuth 即可跨站触发 compose up/down，等于 CSRF 缺口。
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	data, err := p.clients.Call("task.start", map[string]any{"type": typ})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleTaskStatus returns the task's current state.
func (p *panel) handleTaskStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if id == "" {
		http.Error(w, "task_id 必填", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("task.status", map[string]any{"task_id": id})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleTaskLog returns the bounded log lines for a task.
func (p *panel) handleTaskLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if id == "" {
		http.Error(w, "task_id 必填", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("task.log", map[string]any{"task_id": id})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}
