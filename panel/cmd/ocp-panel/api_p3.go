// Package main extends the panel with P3 APIs: nginx site/cert discovery and
// nginx config test/reload.
//
// 只读接口沿用 requireAuth（仅验 session），写接口走 requireWriteAccess 三重门
// 并在每个出口写审计，与 P1/P2 保持同一纪律。nginx.test 本身是只读校验，但
// 通过面板暴露时与 reload 同路径（都是对 nginx 容器的操作），统一走写门。
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// ---------- P3 只读接口 ----------

// handleNginxFull exposes the P3 discovery: sites with cert expiry + proxy
// flag + nginx facts. Backward-compatible superset of /api/nginx.
func (p *panel) handleNginxFull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("nginx.sites.full", nil)
	writeJSON(w, map[string]any{"nginx": data, "agent_error": errStr(err)})
}

// ---------- P3 写接口：nginx test/reload ----------

// nginxActions is the closed write surface for the nginx container.
var nginxActions = map[string]struct{}{
	"TEST": {}, "RELOAD": {},
}

// handleNginxAction runs nginx test or reload behind the three-way write gate.
// Both are container operations; reload changes the running config, test is a
// read-only syntax check that must still be gated so an anonymous caller cannot
// probe the live nginx.
func (p *panel) handleNginxAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeNginxAction); !ok {
		return
	}

	var in struct {
		Action string `json:"action"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "请求格式无效")
		return
	}
	action := strings.ToUpper(strings.TrimSpace(in.Action))
	if _, allowed := nginxActions[action]; !allowed {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxRequestBad, "操作类型不受支持")
		return
	}

	agentAction := "nginx.test"
	if action == "RELOAD" {
		agentAction = "nginx.reload"
	}
	data, err := p.clients.Call(agentAction, nil)
	if err != nil {
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, errStr(err))
		return
	}
	// Agent 可能报告 ok=false（nginx -t 校验失败）——那是 agent 层可用的
	// 真实失败，不是调用失败，需按结果区分。
	if ok, _ := data["ok"].(bool); !ok {
		msg, _ := data["output"].(string)
		if msg == "" {
			msg = "nginx 配置校验失败"
		}
		p.recordNginxRejected(w, r, authaudit.ReasonNginxActionFailed, msg)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeNginxAction, authaudit.OutcomeSuccess, authaudit.ReasonNginxActionSent); err != nil {
		// 审计失败不能放行写操作；回 503 让调用方重试。
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// recordNginxRejected writes one rejection audit entry then the client-facing
// error, mirroring recordRejected but with the nginx type/reason vocabulary.
func (p *panel) recordNginxRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeNginxAction, authaudit.OutcomeRejected, reason); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, http.StatusBadRequest)
}
