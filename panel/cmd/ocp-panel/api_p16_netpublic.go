// Package main — P16 public network info API (read-only).
package main

import (
	"net/http"
)

// handleNetPublic reports real public/local network identity (read-only).
func (p *panel) handleNetPublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	res, err := p.clients.Call("net.public", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}
