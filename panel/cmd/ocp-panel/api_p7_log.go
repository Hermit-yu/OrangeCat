// Package main — P7 nginx access log analysis. Read-only, delegates to the
// agent's nginx.log.analyze (which scans the real combined-format access log
// tail and returns request/byte/status stats for a time window).
package main

import (
	"net/http"
	"strconv"
)

// handleNginxLog returns access-log stats for a window (minutes) via the agent.
func (p *panel) handleNginxLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	windowMin := 60
	if v := r.URL.Query().Get("window_minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowMin = n
		}
	}
	top := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	data, err := p.clients.Call("nginx.log.analyze", map[string]any{"window_minutes": windowMin, "top": top})
	writeJSON(w, map[string]any{"log": data, "agent_error": errStr(err)})
}
