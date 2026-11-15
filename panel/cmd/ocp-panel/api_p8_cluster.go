// Package main — P8 cluster read APIs. Delegates to agent cluster.nodes /
// cluster.node.detail. Read-only (requireAuth); the agent reports the real
// local node and zero peers in single-node deployment (no invented cluster).
package main

import (
	"net/http"
	"strings"
)

// handleClusterNodes returns the real node list (local + live peers).
func (p *panel) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("cluster.nodes", nil)
	writeJSON(w, map[string]any{"cluster": data, "agent_error": errStr(err)})
}

// handleClusterNodeDetail returns one node's detail (local live facts).
func (p *panel) handleClusterNodeDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, map[string]any{"ok": false, "agent_error": "id is required"})
		return
	}
	data, err := p.clients.Call("cluster.node.detail", map[string]any{"id": id})
	writeJSON(w, map[string]any{"node": data, "agent_error": errStr(err)})
}

// handleClusterPair is the pairing write surface. The agent returns a clear
// not_configured result when there is no second host (single-node).
func (p *panel) handleClusterPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("cluster.pair", nil)
	if err != nil {
		http.Error(w, errStr(err), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": data})
}
