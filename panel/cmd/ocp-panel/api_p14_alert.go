// Package main — P14 alert rules + threshold check APIs (read-only).
package main

import (
	"net/http"
)

// handleAlertRules lists the loaded rules (read-only).
func (p *panel) handleAlertRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	res, err := p.clients.Call("alert.rules", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleAlertCheck evaluates rules against real metrics (read-only check).
func (p *panel) handleAlertCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	res, err := p.clients.Call("alert.check", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}
