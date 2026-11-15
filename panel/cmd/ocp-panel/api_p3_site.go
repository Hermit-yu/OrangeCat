// Package main extends the panel with P6 site-change write APIs:
// create/update/delete a reverse-proxy vhost behind the three-way write gate,
// with agent-side template validation, atomic write, backup, nginx -t check
// and rollback. Reuses the P3 nginx_action audit vocabulary (TypeNginxAction).
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// ---------- P6 站点变更写接口 ----------

// handleNginxSiteValidate validates a site payload without writing. It is a
// read-only template check but goes through the write gate because the same
// payload is what a write would consume (fail-closed, no anonymous probing).
func (p *panel) handleNginxSiteValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeNginxAction); !ok {
		return
	}
	var in map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&in); err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "请求格式无效")
		return
	}
	data, err := p.clients.Call("nginx.site.validate", in)
	if err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["error"].(string)
		if msg == "" {
			msg = "站点配置校验失败"
		}
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeNginxAction, authaudit.OutcomeSuccess, authaudit.ReasonNginxActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleNginxSiteSave creates or updates a reverse-proxy vhost. The agent
// validates, backs up, writes atomically, runs nginx -t, reloads on success
// and rolls back on failure.
func (p *panel) handleNginxSiteSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeNginxAction); !ok {
		return
	}
	var in map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&in); err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "请求格式无效")
		return
	}
	// Normalize mode; agent enforces create/update existence gating.
	if m, _ := in["mode"].(string); m == "" {
		in["mode"] = "create"
	}
	data, err := p.clients.Call("nginx.site.save", in)
	if err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["error"].(string)
		if msg == "" {
			msg = "站点保存失败"
		}
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeNginxAction, authaudit.OutcomeSuccess, authaudit.ReasonNginxActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleNginxSiteDelete removes a reverse-proxy vhost after backup, nginx -t
// check and reload, rolling back on failure.
func (p *panel) handleNginxSiteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeNginxAction); !ok {
		return
	}
	var in struct {
		File string `json:"file"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "请求格式无效")
		return
	}
	in.File = strings.TrimSpace(in.File)
	if in.File == "" {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "file 必填")
		return
	}
	data, err := p.clients.Call("nginx.site.delete", map[string]any{"file": in.File})
	if err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["error"].(string)
		if msg == "" {
			msg = "站点删除失败"
		}
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeNginxAction, authaudit.OutcomeSuccess, authaudit.ReasonNginxActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}
