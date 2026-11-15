// Package main — P7 audit export. Reads the same bounded auth-audit.jsonl the
// query endpoint uses and streams it as a CSV or JSONL download. Read-only,
// requireAuth (no write gate); secret fields are always dropped.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// handleAuditExport streams the audit log as CSV or JSONL for download.
// It reuses the same secret-field stripping as handleAudit.
func (p *panel) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if p.auditPath == "" {
		http.Error(w, "audit not configured", http.StatusNotFound)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format != "csv" && format != "jsonl" {
		http.Error(w, "format must be csv or jsonl", http.StatusBadRequest)
		return
	}
	typeFilter := strings.TrimSpace(r.URL.Query().Get("type"))

	f, err := os.Open(p.auditPath)
	if err != nil {
		http.Error(w, "audit read failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Read bounded (same as query endpoint) and filter/strip.
	raw, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil {
		http.Error(w, "audit read failed", http.StatusInternalServerError)
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
		for _, k := range []string{"message", "history", "password", "token", "key", "secret"} {
			delete(ev, k)
		}
		events = append(events, ev)
	}

	ts := strings.ReplaceAll(r.URL.Query().Get("_ts"), ":", "")
	if ts == "" {
		ts = "audit-export"
	}
	if format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.jsonl", ts))
		for _, ev := range events {
			b, _ := json.Marshal(ev)
			_, _ = w.Write(append(b, '\n'))
		}
		return
	}
	// CSV
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", ts))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"at", "type", "outcome", "reason", "client_ip", "method"})
	for _, ev := range events {
		row := []string{
			fmt.Sprintf("%v", ev["at"]),
			fmt.Sprintf("%v", ev["type"]),
			fmt.Sprintf("%v", ev["outcome"]),
			fmt.Sprintf("%v", ev["reason"]),
			fmt.Sprintf("%v", ev["client_ip"]),
			fmt.Sprintf("%v", ev["method"]),
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}
