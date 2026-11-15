package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// aiWriteRequest builds an authenticated-or-not write request with proper
// Origin / CSRF headers so the three-way gate can be exercised deterministically.
func aiWriteRequest(t *testing.T, method, url, body string, withSession bool) *http.Request {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, url, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	req.RemoteAddr = "127.0.0.1:1234"
	req.Host = "localhost:8390"
	req.Header.Set("Origin", "http://localhost:8390")
	if withSession {
		token := "ai-sess-" + time.Now().Format("150405.000000000")
		csrf := "ai-csrf-" + time.Now().Format("150405.000000000")
		addSession(token, session{token: token, csrf: csrf, created: time.Now()}, time.Now())
		t.Cleanup(func() { deleteSession(token) })
		req.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
		req.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return req
}

func TestAIChatRequiresAuth(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{"message":"hi"}`, false)
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401/403 without session", w.Code)
	}
}

func TestAIChatBadOrigin(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{"message":"hi"}`, true)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for cross-origin", w.Code)
	}
}

func TestAIChatRejectsBadBody(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{bad json`, true)
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad body", w.Code)
	}
}

func TestAIChatRejectsEmptyMessage(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{"message":""}`, true)
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty message", w.Code)
	}
}

func TestAIChatRejectsUnknownField(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{"message":"hi","shell":"rm -rf /"}`, true)
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown field", w.Code)
	}
}

func TestAIChatRejectsBadHistory(t *testing.T) {
	p := &panel{}
	r := aiWriteRequest(t, http.MethodPost, "/api/ai/chat", `{"message":"hi","history":"not-an-array"}`, true)
	w := httptest.NewRecorder()
	p.handleAIChat(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad history", w.Code)
	}
}

func TestAIAuditTypeRegistered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	aw, err := authaudit.New(path, 1<<20)
	if err != nil {
		t.Fatalf("new audit writer: %v", err)
	}
	defer aw.Close()
	if err := aw.Record(authaudit.Event{Type: authaudit.TypeAI, Outcome: authaudit.OutcomeSuccess, Reason: authaudit.ReasonAIChatSent, ClientIP: "198.51.100.7", Method: "POST"}); err != nil {
		t.Fatalf("record ai event: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !bytes.Contains(body, []byte(`"type":"ai_chat"`)) {
		t.Fatalf("audit line missing ai_chat type: %s", body)
	}
	if strings.Contains(string(body), "message") || strings.Contains(string(body), "history") {
		t.Fatalf("audit must not carry message/history: %s", body)
	}
}

func TestAICapabilityGet(t *testing.T) {
	// 无真实 agent socket 时，capability 应返回 enabled:false + error（不 panic）。
	p := &panel{clients: agentbridge.New("/run/nonexistent-ocp.sock")}
	r := aiWriteRequest(t, http.MethodGet, "/api/ai/capability", "", true)
	w := httptest.NewRecorder()
	p.handleAICapability(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["enabled"] != false {
		t.Fatalf("want enabled=false when agent unreachable, got %v", body["enabled"])
	}
}
