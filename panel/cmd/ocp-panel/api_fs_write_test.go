package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// fsWriteReq builds a valid write-gated POST with Origin + CSRF triple-gate
// cookies/header satisfied and returns the recorder plus the target path.
func fsWriteReq(t *testing.T, p *panel, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	switch target {
	case "/api/fs/write":
		p.handleFsWrite(w, r)
	case "/api/fs/write/rollback":
		p.handleFsWriteRollback(w, r)
	default:
		t.Fatalf("unhandled target %s", target)
	}
	return w
}

func assertFsWriteAudit(t *testing.T, audit *capturedAuthAudit, wantOutcome, wantReason string) {
	t.Helper()
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Type != authaudit.TypeFsWrite || ev.Outcome != wantOutcome || ev.Reason != wantReason {
		t.Fatalf("unexpected audit event: %+v (want type=%s outcome=%s reason=%s)",
			ev, authaudit.TypeFsWrite, wantOutcome, wantReason)
	}
}

func TestFsWriteRejectsBadOriginAndMissingCSRF(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: &capturedAuthAudit{}}

	// Wrong origin is refused with 403 before session/CSRF checks.
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/fs/write", strings.NewReader(`{"path":"/tmp/a","content":"x"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://evil.example")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleFsWrite(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want 403", w.Code)
	}

	// Missing CSRF header is refused.
	_, csrf2 := seededSession(t)
	r2 := httptest.NewRequest(http.MethodPost, "/api/fs/write", strings.NewReader(`{"path":"/tmp/a","content":"x"}`))
	r2.RemoteAddr = "127.0.0.1:1234"
	r2.Host = "localhost:8390"
	r2.Header.Set("Origin", "http://localhost:8390")
	r2.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r2.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf2})
	w2 := httptest.NewRecorder()
	p.handleFsWrite(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want 403", w2.Code)
	}
}

func TestFsWriteSuccessAndAgentRelay(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{
		"ok": true, "path": "/home/web/conf.d/test.txt", "snapshot": "/var/lib/ocp/fs-snapshots/123-x.snap",
	})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	w := fsWriteReq(t, p, "/api/fs/write", `{"path":"/home/web/conf.d/test.txt","content":"hello"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got.Action != "fs.write" {
		t.Fatalf("agent action = %q, want fs.write", got.Action)
	}
	if got.Params["content"] != "hello" || got.Params["path"] != "/home/web/conf.d/test.txt" {
		t.Fatalf("params not relayed: %v", got.Params)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out["ok"] != true {
		t.Fatalf("ok = %v", out["ok"])
	}
	assertFsWriteAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonFsWriteSent)
}

func TestFsWriteRejectsEmptyPathOrContent(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	for _, body := range []string{`{"path":"","content":"x"}`, `{"path":"/tmp/a","content":""}`} {
		w := fsWriteReq(t, p, "/api/fs/write", body)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out["ok"] != false {
			t.Fatalf("expected ok=false for body %s, got %s", body, w.Body.String())
		}
	}
}

func TestFsRollbackSuccessAndAgentRelay(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{
		"ok": true, "path": "/home/web/conf.d/test.txt", "size": 5,
	})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	w := fsWriteReq(t, p, "/api/fs/write/rollback", `{"snapshot":"/var/lib/ocp/fs-snapshots/123.snap","path":"/home/web/conf.d/test.txt"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got.Action != "fs.write.rollback" {
		t.Fatalf("agent action = %q, want fs.write.rollback", got.Action)
	}
	assertFsWriteAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonFsRollbackSent)
}
