// Package main extends the panel with P1 APIs: services, health, diagnostics,
// process kill, and history query. All handlers reuse the existing auth/CSRF
// infrastructure from main.go. No new state is invented; every handler
// delegates to the agent via agentbridge or reads SQLite history.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/history"
)

// ---------- P1 APIs ----------

func (p *panel) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	params := map[string]any{}
	if filter != "" {
		params["filter"] = filter
	}
	data, err := p.clients.Call("system.services", params)
	writeJSON(w, map[string]any{"services": data, "agent_error": errStr(err)})
}

// handleChangePassword 修改管理员密码（切片 F）。
// 校验当前密码（常量时间比较），新密码 ≥12 字符且含字母与数字；
// 原子写回 panel-password (0600)，更新内存值，记审计。
func (p *panel) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.rejectAuth(w, r, authaudit.TypeLogin, "invalid_json", http.StatusBadRequest, "请求格式无效")
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		p.rejectAuth(w, r, authaudit.TypeLogin, "invalid_json", http.StatusBadRequest, "请求格式无效")
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.CurrentPassword), []byte(p.password)) != 1 {
		p.rejectAuth(w, r, authaudit.TypeLogin, "bad_credentials", http.StatusUnauthorized, "当前密码错误")
		return
	}
	if len(in.NewPassword) < 12 || !hasLetterAndDigit(in.NewPassword) {
		p.rejectAuth(w, r, authaudit.TypeLogin, "invalid_password", http.StatusBadRequest, "新密码须至少 12 字符且包含字母和数字")
		return
	}
	// 原子写回：tmp + rename，保留 0600
	dir := dirOf(p.pwPath)
	token, tokenErr := randomToken(6)
	if tokenErr != nil {
		p.rejectAuth(w, r, authaudit.TypeLogin, "write_failed", http.StatusInternalServerError, "生成临时文件名失败")
		return
	}
	tmp := p.pwPath + ".tmp-" + token
	if err := os.WriteFile(tmp, []byte(in.NewPassword), 0600); err != nil {
		p.rejectAuth(w, r, authaudit.TypeLogin, "write_failed", http.StatusInternalServerError, "写密码文件失败")
		return
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		p.rejectAuth(w, r, authaudit.TypeLogin, "write_failed", http.StatusInternalServerError, "设置权限失败")
		return
	}
	if err := os.Rename(tmp, p.pwPath); err != nil {
		os.Remove(tmp)
		p.rejectAuth(w, r, authaudit.TypeLogin, "write_failed", http.StatusInternalServerError, "替换密码文件失败")
		return
	}
	p.mu.Lock()
	p.password = in.NewPassword
	p.mu.Unlock()
	_ = dir
	p.recordAudit(r, authaudit.TypePassword, authaudit.ReasonPasswordChanged, "success", "")
	writeJSON(w, map[string]any{"ok": true, "message": "密码已更新，下次登录用新密码"})
}

// hasLetterAndDigit reports whether s contains at least one letter and one digit.
func hasLetterAndDigit(s string) bool {
	letter, digit := false, false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letter = true
		}
		if r >= '0' && r <= '9' {
			digit = true
		}
		if letter && digit {
			return true
		}
	}
	return false
}

// recordAudit 记录一次审计事件（带客户端 IP）。
func (p *panel) recordAudit(r *http.Request, typ, reason, outcome, detail string) {
	if p.authAudit != nil {
		ev := authaudit.Event{
			Type:     typ,
			Reason:   reason,
			Outcome:  outcome,
			ClientIP: p.clientIP(r),
			Method:   r.Method,
		}
		_ = p.authAudit.Record(ev)
	}
	_ = detail
}

func (p *panel) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	params := map[string]any{}
	if scope != "" {
		params["scope"] = scope
	}
	data, err := p.clients.Call("health.check", params)
	writeJSON(w, map[string]any{"report": data, "agent_error": errStr(err)})
}

func (p *panel) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	params := map[string]any{}
	if h := strings.TrimSpace(r.URL.Query().Get("host")); h != "" {
		params["host"] = h
	}
	if u := strings.TrimSpace(r.URL.Query().Get("url")); u != "" {
		params["url"] = u
	}
	data, err := p.clients.Call("net.diagnostics", params)
	writeJSON(w, map[string]any{"diagnostics": data, "agent_error": errStr(err)})
}

// handleAudit returns the most recent audit events from auth-audit.jsonl.
// It reads the tail of the real log file (bounded), filters by type, and never
// exposes secret material (message/history/password fields are dropped).
func (p *panel) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if p.auditPath == "" {
		writeJSON(w, map[string]any{"ok": true, "events": []any{}, "count": 0})
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	typeFilter := strings.TrimSpace(r.URL.Query().Get("type"))
	f, err := os.Open(p.auditPath)
	if err != nil {
		writeJSON(w, map[string]any{"ok": true, "events": []any{}, "count": 0, "error": errStr(err)})
		return
	}
	defer f.Close()
	// Read the whole bounded file (max ~1 MiB) then tail.
	raw, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil {
		writeJSON(w, map[string]any{"ok": true, "events": []any{}, "count": 0, "error": errStr(err)})
		return
	}
	var events []map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if typeFilter != "" && ev["type"] != typeFilter {
			continue
		}
		// Drop anything that could carry a secret.
		for _, k := range []string{"message", "history", "password", "token", "key", "secret"} {
			delete(ev, k)
		}
		events = append(events, ev)
	}
	// Tail: keep the newest `limit`.
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	writeJSON(w, map[string]any{"ok": true, "events": events, "count": len(events)})
}

func (p *panel) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeProcessKill); !ok {
		return
	}

	var in struct {
		PID    int    `json:"pid"`
		Signal string `json:"signal"`
		Force  bool   `json:"force"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.rejectAuth(w, r, authaudit.TypeProcessKill, authaudit.ReasonKillRequestInvalid, http.StatusBadRequest, "请求格式无效")
		return
	}
	if in.PID < 1 {
		p.rejectAuth(w, r, authaudit.TypeProcessKill, authaudit.ReasonKillRequestInvalid, http.StatusBadRequest, "pid 无效")
		return
	}
	// PID 1 是 systemd（init）。Web 层直接拒绝：误杀会让整机 systemd 退出，
	// 面板侧不应存在触达 init 信号的路径，也不依赖 Agent 是否愿意放行。
	if in.PID == 1 {
		p.rejectAuth(w, r, authaudit.TypeProcessKill, authaudit.ReasonKillPIDInitForbidden, http.StatusForbidden, "拒绝操作：PID 1 是系统 init")
		return
	}
	if in.Signal != "" && in.Signal != "TERM" && in.Signal != "KILL" {
		p.rejectAuth(w, r, authaudit.TypeProcessKill, authaudit.ReasonKillRequestInvalid, http.StatusBadRequest, "signal 必须是 TERM 或 KILL")
		return
	}
	if in.Signal == "KILL" && !in.Force {
		p.rejectAuth(w, r, authaudit.TypeProcessKill, authaudit.ReasonKillRequestInvalid, http.StatusBadRequest, "SIGKILL 必须显式 force=true")
		return
	}
	params := map[string]any{"pid": float64(in.PID)}
	if in.Signal != "" {
		params["signal"] = in.Signal
	}
	if in.Force {
		params["force"] = true
	}
	data, err := p.clients.Call("process.kill", params)
	if err != nil {
		// Agent 调用失败（socket 不通、动作拒绝等）必须作为失败返回，
		// 不能与成功共用 200，否则前端会把"未执行"显示成"已执行"。
		if p.recordAuth(r, authaudit.TypeProcessKill, authaudit.OutcomeRejected, authaudit.ReasonKillRejected) != nil {
			log.Printf("进程结束审计写入失败: %v", err)
		}
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": errStr(err)})
		return
	}
	// Agent 即便调用成功也可能 sent=false（pid 已不存在 / 无权限 / 信号失败）。
	// 只有真正发出信号才算成功，其余一律走失败码，避免前端误显示"已结束"。
	if sent, _ := data["sent"].(bool); !sent {
		reason, _ := data["reason"].(string)
		if reason == "" {
			reason = "信号未发出"
		}
		if p.recordAuth(r, authaudit.TypeProcessKill, authaudit.OutcomeRejected, authaudit.ReasonKillRejected) != nil {
			log.Printf("进程结束审计写入失败: %v", reason)
		}
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, map[string]any{"ok": false, "result": data, "agent_error": reason})
		return
	}
	if p.recordAuth(r, authaudit.TypeProcessKill, authaudit.OutcomeSuccess, authaudit.ReasonKillSignalSent) != nil {
		log.Printf("进程结束审计写入失败（信号已发送，未留痕）: pid=%d", in.PID)
	}
	writeJSON(w, map[string]any{"ok": true, "result": data, "agent_error": ""})
}

func (p *panel) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().Unix()
	from, to, rangeErr := parseRange(r, now)
	if rangeErr != nil {
		http.Error(w, rangeErr.Error(), http.StatusBadRequest)
		return
	}
	level := r.URL.Query().Get("level")
	if level == "" {
		level = "raw"
	}
	store, err := history.Open("/var/lib/ocp/metrics.db")
	if err != nil {
		writeJSON(w, map[string]any{"error": "history database unavailable: " + err.Error()})
		return
	}
	defer store.Close()

	switch level {
	case "raw":
		samples, err := store.QuerySamples(from, to)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"level": "raw", "samples": samples, "count": len(samples), "from": from, "to": to})
	case "hourly":
		rows, err := store.QueryHourly(from, to)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"level": "hourly", "rows": rows, "count": len(rows), "from": from, "to": to})
	default:
		http.Error(w, "level must be raw or hourly", http.StatusBadRequest)
	}
}

// parseRange extracts from/to unix seconds from query params, with defaults.
// 非法或超窗口的范围返回错误，由调用方按 400 拒绝，不再静默降级为默认值。
const maxHistorySpanSeconds = 366 * 24 * 3600

func parseRange(r *http.Request, now int64) (int64, int64, error) {
	from := now - 3600
	to := now
	if f := r.URL.Query().Get("from"); f != "" {
		v, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("from 必须是 unix 秒时间戳")
		}
		from = v
	}
	if t := r.URL.Query().Get("to"); t != "" {
		v, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("to 必须是 unix 秒时间戳")
		}
		to = v
	}
	// 只读查询的防御：拒绝过去之外太远的边界与负向窗口，
	// 窗口上限同时挡住 from=0 这种全库扫描。
	if from < 0 || to < 0 {
		return 0, 0, fmt.Errorf("时间范围不能早于 1970")
	}
	if to < from {
		return 0, 0, fmt.Errorf("to 不能早于 from")
	}
	if to-from > maxHistorySpanSeconds {
		return 0, 0, fmt.Errorf("时间范围过长（上限 %d 天）", maxHistorySpanSeconds/86400)
	}
	return from, to, nil
}
