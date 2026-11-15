package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// 切片 A：AI 助手 API。
//
// ai.chat 是一次性请求/响应（非流式）。写路径走 requireWriteAccess 三重门
// （Origin + session + CSRF）并落审计；只读能力状态走 requireAuth。
// 参数全部透传给 agent 的 ai.chat（agent 侧已做参数白名单 + 长度上限 +
// key 脱敏），panel 不构造任何自由 shell，不透传任意字段。

// handleAIChat sends one user message to the configured LLM endpoint.
func (p *panel) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeAI); !ok {
		return
	}
	var in struct {
		Message string          `json:"message"`
		History json.RawMessage `json:"history"`
		Model   string          `json:"model"`
		System  string          `json:"system"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordAIRejected(w, r, authaudit.ReasonAIChatRequestBad, "请求格式无效")
		return
	}
	in.Message = strings.TrimSpace(in.Message)
	if in.Message == "" {
		p.recordAIRejected(w, r, authaudit.ReasonAIChatRequestBad, "message 必填")
		return
	}
	if len(in.Message) > 32<<10 {
		p.recordAIRejected(w, r, authaudit.ReasonAIChatRequestBad, "message 过长")
		return
	}
	params := map[string]any{"message": in.Message}
	// history 只透传 JSON 数组，agent 侧解析并强制条数/字符上限。
	if len(in.History) > 0 {
		var arr []any
		if err := json.Unmarshal(in.History, &arr); err != nil {
			p.recordAIRejected(w, r, authaudit.ReasonAIChatRequestBad, "history 格式无效")
			return
		}
		params["history"] = arr
	}
	if in.Model != "" {
		params["model"] = in.Model
	}
	if in.System != "" {
		params["system"] = in.System
	}
	data, err := p.clients.Call("ai.chat", params)
	if err != nil {
		p.recordAIRejected(w, r, authaudit.ReasonAIChatFailed, errStr(err))
		return
	}
	if err := p.recordAuth(r, authaudit.TypeAI, authaudit.OutcomeSuccess, authaudit.ReasonAIChatSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleAICapability reports the real AI capability state from the agent.
func (p *panel) handleAICapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("ai.status", map[string]any{})
	if err != nil {
		writeJSON(w, map[string]any{"ok": true, "enabled": false, "error": errStr(err)})
		return
	}
	enabled, _ := data["enabled"].(bool)
	model, _ := data["model"].(string)
	writeJSON(w, map[string]any{"ok": true, "enabled": enabled, "model": model})
}

// recordAIRejected writes one rejection audit entry then the client-facing error.
func (p *panel) recordAIRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeAI, authaudit.OutcomeRejected, reason); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
}
