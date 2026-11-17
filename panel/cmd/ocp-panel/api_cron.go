package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// cronWriteOps is the closed cron write surface. list is read-only and uses a
// separate handler; add/remove/toggle rewrite the root crontab and are gated by
// the same three-way write access check (Origin + session + CSRF) as every
// other panel write.
var cronWriteOps = map[string]bool{"add": true, "remove": true, "toggle": true}

// handleCronList returns the local root crontab parsed into indexed jobs.
// This is read-only, so it sits behind requireAuth (session) in the route
// table like the other list endpoints — not behind the CSRF write gate, which
// a GET cannot satisfy.
func (p *panel) handleCronList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("cron.list", nil)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err), "jobs": []any{}})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "data": data})
}

// handleCronAction performs one cron write operation. The agent re-reads the
// crontab on every call and re-derives indices, so a stale panel list cannot
// delete the wrong line. Every accepted call is audited as cron_action.
func (p *panel) handleCronAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeCronAction); !ok {
		return
	}

	var in struct {
		Op    string `json:"op"`
		Line  string `json:"line"`
		Index *int   `json:"index"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		if err == io.EOF {
			http.Error(w, "body required", http.StatusBadRequest)
			return
		}
		p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != nil && err != io.EOF {
		p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	op := strings.ToLower(strings.TrimSpace(in.Op))
	if !cronWriteOps[op] {
		p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
		http.Error(w, "unsupported_op", http.StatusBadRequest)
		return
	}

	var params map[string]any
	switch op {
	case "add":
		line := strings.TrimSpace(in.Line)
		if line == "" {
			p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
			http.Error(w, "line_required", http.StatusBadRequest)
			return
		}
		if len(line) > 1000 {
			p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
			http.Error(w, "line_too_long", http.StatusBadRequest)
			return
		}
		params = map[string]any{"line": line}
	case "remove", "toggle":
		if in.Index == nil {
			p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
			http.Error(w, "index_required", http.StatusBadRequest)
			return
		}
		if *in.Index < 0 {
			p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronRequestBad)
			http.Error(w, "index_invalid", http.StatusBadRequest)
			return
		}
		params = map[string]any{"index": *in.Index}
	}

	data, err := p.clients.Call("cron."+op, params)
	if err != nil {
		p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronActionFailed)
		writeJSON(w, map[string]any{"ok": false, "agent_error": errStr(err)})
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeRejected, authaudit.ReasonCronActionFailed)
		writeJSON(w, map[string]any{"ok": false, "result": data})
		return
	}
	if err := p.recordAuth(r, authaudit.TypeCronAction, authaudit.OutcomeSuccess, authaudit.ReasonCronActionSent); err != nil {
		log.Printf("cron audit write failed: %v", err)
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}
