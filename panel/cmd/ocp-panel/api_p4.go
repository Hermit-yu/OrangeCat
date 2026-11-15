// Package main extends the panel with P4 slice 1: read-only file browsing
// (list / read / stat). 只读接口沿用 requireAuth（仅验 session），权威路径校验在
// agent 侧 resolveFsPath（绝对路径 / NUL 拒绝 / Clean 吸收 ..），面板层只检查
// path 非空。大目录、大文件、二进制文件的界限由 agent 硬性截断并标记。
package main

import (
	"net/http"
	"strings"
)

// handleFsList lists one absolute directory path.
func (p *panel) handleFsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "path 参数缺失", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("fs.list", map[string]any{"path": path})
	writeJSON(w, map[string]any{"list": data, "agent_error": errStr(err)})
}

// handleFsRead returns bounded file content (truncation + binary flag from agent).
func (p *panel) handleFsRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "path 参数缺失", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("fs.read", map[string]any{"path": path})
	writeJSON(w, map[string]any{"file": data, "agent_error": errStr(err)})
}

// handleFsStat reports metadata for one path without listing it.
func (p *panel) handleFsStat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "path 参数缺失", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("fs.stat", map[string]any{"path": path})
	writeJSON(w, map[string]any{"stat": data, "agent_error": errStr(err)})
}
