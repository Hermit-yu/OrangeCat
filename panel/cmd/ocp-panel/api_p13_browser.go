// Package main — P13 isolated browser APIs. Status read-only; open/navigate/
// close are write-gated + audited. The browser runs as an isolated Chromium
// process (not sharing Agent privileges) and is off by default.
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// handleBrowserStatus reports browser enabled/tabs (read-only).
func (p *panel) handleBrowserStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	res, err := p.clients.Call("browser.status", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "status": res})
}

// handleBrowserOpen opens a tab in the isolated browser (write gate + audit).
func (p *panel) handleBrowserOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if in.URL == "" {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "URL 无效")
		return
	}
	res, err := p.clients.Call("browser.open", map[string]any{"url": in.URL})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "浏览器打开失败")
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleBrowserNavigate navigates a tab (write gate + audit).
func (p *panel) handleBrowserNavigate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Tab string `json:"tab"`
		URL string `json:"url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if in.URL == "" {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "URL 无效")
		return
	}
	res, err := p.clients.Call("browser.navigate", map[string]any{"tab": in.Tab, "url": in.URL})
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "导航失败")
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleBrowserClose closes the isolated browser (write gate + audit).
func (p *panel) handleBrowserClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	res, err := p.clients.Call("browser.close", nil)
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "浏览器关闭失败")
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleBrowserURL reports the current URL of a tab (read-only).
func (p *panel) handleBrowserURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	tab := strings.TrimSpace(r.URL.Query().Get("tab"))
	res, err := p.clients.Call("browser.url", map[string]any{"tab": tab})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}
