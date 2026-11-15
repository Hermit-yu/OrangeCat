// Package main — P11 application catalog & ecosystem APIs.
// Catalog is read-only; install/uninstall are write-gated + audited.
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// handleAppsCatalog lists the catalog with install status (read-only).
func (p *panel) handleAppsCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	res, err := p.clients.Call("apps.catalog", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "catalog": res})
}

// handleAppsInstall installs a catalog app via async task (compose up can
// exceed the 60s gateway timeout; run as background task and poll status).
func (p *panel) handleAppsInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "应用名无效")
		return
	}
	res, err := p.clients.Call("task.start", map[string]any{"type": "app_install", "name": in.Name})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "安装任务启动失败")
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleAppsUninstall stops a catalog app via compose down (write gate + audit).
func (p *panel) handleAppsUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "应用名无效")
		return
	}
	res, err := p.clients.Call("task.start", map[string]any{"type": "app_uninstall", "name": in.Name})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "卸载任务启动失败")
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}
