// Package main — P7 notification APIs. Delegates to the agent notify actions.
// notify.status is read-only (requireAuth); notify.test / notify.alert are
// writes (three-way gate + audit). The agent owns credential handling (env
// injected, never logged) and returns a clear "not configured" when no token.
package main

import (
	"encoding/json"
	"net/http"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// handleNotifyStatus reports notification configuration (read-only).
func (p *panel) handleNotifyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("notify.status", nil)
	writeJSON(w, map[string]any{"notify": data, "agent_error": errStr(err)})
}

// handleNotifyTest sends a test message (write gate).
func (p *panel) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Message string `json:"message"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	data, err := p.clients.Call("notify.test", map[string]any{"message": in.Message})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["error"].(string)
		if msg == "" {
			msg = "通知发送失败"
		}
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleNotifyAlert raises an alert (write gate).
func (p *panel) handleNotifyAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	data, err := p.clients.Call("notify.alert", map[string]any{"severity": in.Severity, "message": in.Message})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["error"].(string)
		if msg == "" {
			msg = "告警发送失败"
		}
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}
