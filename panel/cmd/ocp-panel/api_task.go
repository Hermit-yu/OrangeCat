package main

import (
	"net/http"
	"strings"
)

// P4-5 切片：后台任务状态 API（只读，requireAuth 不涉写门）。
//
// 任务在 agent 进程内异步执行；panel 只转发 start/status/log 请求并透出
// 结果。任务类型白名单在 agent 侧强制（hostdiag），panel 不做命令构造。

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
