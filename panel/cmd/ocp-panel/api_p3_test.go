package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// nginxRequest builds a fully-authorized POST for the nginx write endpoint.
func nginxRequest(t *testing.T, body, origin string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/nginx/action", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return httptest.NewRecorder(), r
}

func assertNginxAudit(t *testing.T, audit *capturedAuthAudit, wantOutcome, wantReason string) {
	t.Helper()
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Type != authaudit.TypeNginxAction || ev.Outcome != wantOutcome || ev.Reason != wantReason {
		t.Fatalf("unexpected audit event: %+v (want type=%s outcome=%s reason=%s)",
			ev, authaudit.TypeNginxAction, wantOutcome, wantReason)
	}
}

// TestNginxActionRequiresPost guards the write endpoint against a GET smuggle.
func TestNginxActionRequiresPost(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodGet, "/api/nginx/action", nil)
	w := httptest.NewRecorder()
	p.handleNginxAction(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

// TestNginxActionGateOrdering exercises all three write gates on the P3 surface.
func TestNginxActionGateOrdering(t *testing.T) {
	const body = `{"action":"RELOAD"}`

	t.Run("foreign origin", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := nginxRequest(t, body, "https://evil.example.com")
		p.handleNginxAction(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertNginxAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonOriginMismatch)
	})

	t.Run("missing session", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		r := httptest.NewRequest(http.MethodPost, "/api/nginx/action", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Host = "localhost:8390"
		w := httptest.NewRecorder()
		p.handleNginxAction(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertNginxAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonSessionMissing)
	})

	t.Run("missing csrf header", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := nginxRequest(t, body, "")
		r.Header.Del("X-CSRF-Token")
		p.handleNginxAction(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertNginxAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonCSRFFailed)
	})
}

// TestNginxActionRejectsUnknownAction pins the closed write surface.
func TestNginxActionRejectsUnknownAction(t *testing.T) {
	for _, body := range []string{
		`{"action":"RESTART"}`,
		`{"action":"reload;rm -rf /"}`,
		`{"action":""}`,
		`{"action":"RELOAD","extra":"leak"}`,
	} {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := nginxRequest(t, body, "")
		p.handleNginxAction(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status = %d, want 400", body, w.Code)
		}
		assertNginxAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonNginxRequestBad)
	}
}

// TestNginxActionSuccessPath verifies reload success end to end: gate passes,
// agent called with nginx.reload, success audit written.
func TestNginxActionSuccessPath(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{"ok": true, "running": true, "output": "reload signal sent"})
	audit := &capturedAuthAudit{}
	p := &panel{
		password: "secret", attempts: map[string]int{}, authAudit: audit,
		clients: agentbridge.New(sock),
	}
	w, r := nginxRequest(t, `{"action":"reload"}`, "")
	p.handleNginxAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got.Action != "nginx.reload" {
		t.Fatalf("agent action = %q, want nginx.reload", got.Action)
	}
	assertNginxAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonNginxActionSent)
}

// TestNginxActionReportsNginxFailureAsRejected pins that agent ok=false (e.g.
// nginx -t syntax error) is a failure with its own audit reason.
func TestNginxActionReportsNginxFailureAsRejected(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{"ok": false, "running": false, "output": "syntax error"})
	audit := &capturedAuthAudit{}
	p := &panel{
		password: "secret", attempts: map[string]int{}, authAudit: audit,
		clients: agentbridge.New(sock),
	}
	w, r := nginxRequest(t, `{"action":"test"}`, "")
	p.handleNginxAction(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", w.Code, w.Body.String())
	}
	assertNginxAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonNginxActionFailed)
}
