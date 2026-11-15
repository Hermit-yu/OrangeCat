// Package main extends the panel with P6 system-management write APIs:
// hostname / timezone set (with dry-run preview + audit) and a read-only
// SSH status. All writes go through the three-way gate with audit; the
// system actions are persistent host changes, so a dry_run preview is always
// available and the real apply is explicit (dry_run=false).
package main

import (
	"encoding/json"
	"net/http"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// ---------- P6 系统管理写接口 ----------

// handleSystemHostname sets the hostname. dry_run=true returns a preview
// (current vs new) without mutating; dry_run=false applies after backup.
func (p *panel) handleSystemHostname(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
		DryRun   bool   `json:"dry_run"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	params := map[string]any{"hostname": in.Hostname, "dry_run": in.DryRun}
	data, err := p.clients.Call("system.hostname.set", params)
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, errStr(err))
		return
	}
	if !in.DryRun {
		if ok, _ := data["applied"].(bool); !ok && data["reason"] != "unchanged" {
			msg, _ := data["error"].(string)
			if msg == "" {
				msg = "主机名设置失败"
			}
			p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, msg)
			return
		}
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleSystemTimezone sets the system timezone. Same dry_run semantics.
func (p *panel) handleSystemTimezone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Timezone string `json:"timezone"`
		DryRun   bool   `json:"dry_run"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	params := map[string]any{"timezone": in.Timezone, "dry_run": in.DryRun}
	data, err := p.clients.Call("system.timezone.set", params)
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, errStr(err))
		return
	}
	if !in.DryRun {
		if ok, _ := data["applied"].(bool); !ok && data["reason"] != "unchanged" {
			msg, _ := data["error"].(string)
			if msg == "" {
				msg = "时区设置失败"
			}
			p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, msg)
			return
		}
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleSystemSSH is read-only: reports SSH service state + effective port,
// without exposing any port change. Goes through requireAuth (read surface).
func (p *panel) handleSystemSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("system.ssh.status", nil)
	writeJSON(w, map[string]any{"ssh": data, "agent_error": errStr(err)})
}

// recordSystemRejected writes one rejection audit entry then the client error.
func (p *panel) recordSystemRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeRejected, reason); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
}
