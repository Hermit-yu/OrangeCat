package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// ptyWriteRequest builds an authenticated-or-not write request with proper
// Origin / CSRF headers so the three-way gate can be exercised deterministically.
func ptyWriteRequest(t *testing.T, method, url, body string, withSession bool) *http.Request {
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
		token, csrf := seededSessionForPTY(t)
		req.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
		req.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return req
}

// seededSessionForPTY creates a unique session and cleans it up after the test.
func seededSessionForPTY(t *testing.T) (string, string) {
	t.Helper()
	token := "pty-sess-" + time.Now().Format("150405.000000000")
	csrf := "pty-csrf-" + time.Now().Format("150405.000000000")
	addSession(token, session{token: token, csrf: csrf, created: time.Now()}, time.Now())
	t.Cleanup(func() { deleteSession(token) })
	return token, csrf
}

func TestPTYOpenRequiresAuth(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/open", `{"command":"bash"}`, false)
	w := httptest.NewRecorder()
	p.handlePTYOpen(w, r)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 401/403 without session", w.Code)
	}
}

func TestPTYOpenBadOrigin(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/open", `{"command":"bash"}`, true)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	p.handlePTYOpen(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for cross-origin", w.Code)
	}
}

func TestPTYOpenRejectsBadBody(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/open", `{bad json`, true)
	w := httptest.NewRecorder()
	p.handlePTYOpen(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad body", w.Code)
	}
}

func TestPTYInputRejectsEmptySession(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/input", `{"data":"ls"}`, true)
	w := httptest.NewRecorder()
	p.handlePTYInput(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing session_id", w.Code)
	}
}

func TestPTYCloseRejectsEmptySession(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/close", `{}`, true)
	w := httptest.NewRecorder()
	p.handlePTYClose(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing session_id", w.Code)
	}
}

func TestPTYStatusRejectsMissingSession(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodGet, "/api/pty/status", "", true)
	w := httptest.NewRecorder()
	p.handlePTYStatus(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing session_id", w.Code)
	}
}

func TestPTYAuditTypeRegistered(t *testing.T) {
	// The audit writer must accept the pty type; build a real writer in a temp
	// dir and record one success event.
	dir := t.TempDir()
	path := dir + "/audit.jsonl"
	aw, err := authaudit.New(path, 1<<20)
	if err != nil {
		t.Fatalf("new audit writer: %v", err)
	}
	defer aw.Close()
	if err := aw.Record(authaudit.Event{Type: authaudit.TypePTY, Outcome: authaudit.OutcomeSuccess, Reason: authaudit.ReasonPTYOpenSent, ClientIP: "198.51.100.7"}); err != nil {
		t.Fatalf("record pty event: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !bytes.Contains(body, []byte(`"type":"pty"`)) {
		t.Fatalf("audit line missing pty type: %s", body)
	}
}

func TestPTYOpenValidatesCommand(t *testing.T) {
	p := &panel{}
	r := ptyWriteRequest(t, http.MethodPost, "/api/pty/open", `{"command":""}`, true)
	w := httptest.NewRecorder()
	p.handlePTYOpen(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty command", w.Code)
	}
}
