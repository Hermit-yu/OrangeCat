package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// P5 切片：受控 PTY 终端 API。
//
// 终端是最高风险的写路径（root 完整 shell），所有写操作（open/input/close）
// 走 requireWriteAccess 三重门（Origin + session + CSRF）并逐次落审计；只读
// status/list 走 requireAuth（仅验 session）。命令白名单在 agent 侧强制
// （bash/sh），panel 只透传固定命令字段，不构造任何 shell 参数。

// handlePTYOpen starts a terminal session.
func (p *panel) handlePTYOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypePTY); !ok {
		return
	}
	var in struct {
		Command string `json:"command"`
		Rows    int    `json:"rows"`
		Cols    int    `json:"cols"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYOpenRequestBad, "请求格式无效")
		return
	}
	in.Command = strings.TrimSpace(in.Command)
	if in.Command == "" {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYOpenRequestBad, "命令必填")
		return
	}
	params := map[string]any{"command": in.Command}
	if in.Rows > 0 {
		params["rows"] = in.Rows
	}
	if in.Cols > 0 {
		params["cols"] = in.Cols
	}
	data, err := p.clients.Call("pty.open", params)
	if err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYOpenFailed, errStr(err))
		return
	}
	if err := p.recordAuth(r, authaudit.TypePTY, authaudit.OutcomeSuccess, authaudit.ReasonPTYOpenSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handlePTYStatus polls incremental output from offset.
func (p *panel) handlePTYStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if id == "" {
		http.Error(w, "session_id 必填", http.StatusBadRequest)
		return
	}
	params := map[string]any{"session_id": id}
	if off := r.URL.Query().Get("offset"); off != "" {
		n, err := strconv.Atoi(off)
		if err != nil || n < 0 {
			http.Error(w, "offset 无效", http.StatusBadRequest)
			return
		}
		params["offset"] = n
	}
	data, err := p.clients.Call("pty.status", params)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handlePTYInput writes user input to a session.
func (p *panel) handlePTYInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypePTY); !ok {
		return
	}
	var in struct {
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYInputRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.SessionID) == "" {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYInputRequestBad, "session_id 必填")
		return
	}
	data, err := p.clients.Call("pty.input", map[string]any{"session_id": in.SessionID, "data": in.Data})
	if err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYInputFailed, errStr(err))
		return
	}
	if err := p.recordAuth(r, authaudit.TypePTY, authaudit.OutcomeSuccess, authaudit.ReasonPTYInputSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handlePTYClose actively terminates a session.
func (p *panel) handlePTYClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypePTY); !ok {
		return
	}
	var in struct {
		SessionID string `json:"session_id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYCloseRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.SessionID) == "" {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYCloseRequestBad, "session_id 必填")
		return
	}
	data, err := p.clients.Call("pty.close", map[string]any{"session_id": in.SessionID})
	if err != nil {
		p.recordPTYRejected(w, r, authaudit.ReasonPTYCloseFailed, errStr(err))
		return
	}
	if err := p.recordAuth(r, authaudit.TypePTY, authaudit.OutcomeSuccess, authaudit.ReasonPTYCloseSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handlePTYList lists active sessions.
func (p *panel) handlePTYList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("pty.list", map[string]any{})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// recordPTYRejected writes one rejection audit entry then the client-facing error.
func (p *panel) recordPTYRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypePTY, authaudit.OutcomeRejected, reason); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
}
