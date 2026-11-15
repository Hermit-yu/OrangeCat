// Package main extends the panel with P1 APIs: services, health, diagnostics,
// process kill, and history query. All handlers reuse the existing auth/CSRF
// infrastructure from main.go. No new state is invented; every handler
// delegates to the agent via agentbridge or reads SQLite history.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
