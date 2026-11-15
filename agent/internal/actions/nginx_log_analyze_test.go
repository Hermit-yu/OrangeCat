package actions

import (
	"testing"
	"time"
)

// TestParseAccessLine parses a real combined-format line.
func TestParseAccessLine(t *testing.T) {
	line := `223.73.45.27 - - [07/Oct/2026:02:00:04 +0000] "GET /api/clients/v2/rpc?token=abc HTTP/1.1" 444 0 "-" "Go-http-client/1.1"`
	ts, ip, path, status, bytes, ok := parseAccessLine(line)
	if !ok {
		t.Fatalf("line not parsed")
	}
	if ip != "223.73.45.27" {
		t.Fatalf("ip = %q", ip)
	}
	if path != "/api/clients/v2/rpc?token=abc" {
		t.Fatalf("path = %q", path)
	}
	if status != "444" {
		t.Fatalf("status = %q", status)
	}
	if bytes != 0 {
		t.Fatalf("bytes = %d", bytes)
	}
	want, _ := time.Parse("02/Jan/2006:15:04:05", "07/Oct/2026:02:00:04")
	if ts != want.Unix() {
		t.Fatalf("ts = %d want %d", ts, want.Unix())
	}
}

// TestParseAccessLineNormalLine parses a 200 response with body bytes.
func TestParseAccessLineNormalLine(t *testing.T) {
	line := `1.2.3.4 - - [10/Nov/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`
	ts, ip, path, status, bytes, ok := parseAccessLine(line)
	if !ok || ip != "1.2.3.4" || path != "/index.html" || status != "200" || bytes != 512 || ts <= 0 {
		t.Fatalf("got ts=%d ip=%q path=%q status=%q bytes=%d ok=%v", ts, ip, path, status, bytes, ok)
	}
}

// TestNginxLogAnalyzeRejectsParams: extra fields are rejected.
func TestNginxLogAnalyzeRejectsParams(t *testing.T) {
	if _, err := NginxLogAnalyze(t.Context(), map[string]any{"window_minutes": 60, "extra": "x"}); err == nil {
		t.Fatalf("extra field should be rejected")
	}
	if _, err := NginxLogAnalyze(t.Context(), map[string]any{}); err == nil {
		t.Fatalf("empty params should be rejected")
	}
}
