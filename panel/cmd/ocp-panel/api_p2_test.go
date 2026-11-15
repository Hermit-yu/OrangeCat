package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// containerRequest builds a fully-authorized write request (same origin, valid
// session cookie, CSRF cookie + header) so each test can break exactly one gate.
func containerRequest(t *testing.T, body, origin string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/docker/action", strings.NewReader(body))
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

// TestContainerActionRequiresPost guards the write endpoint against a GET smuggle.
func TestContainerActionRequiresPost(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodGet, "/api/docker/action", nil)
	w := httptest.NewRecorder()
	p.handleContainerAction(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

// TestContainerActionGateOrdering exercises all three gates of requireWriteAccess
// on the new write surface: foreign origin, missing session, missing CSRF.
func TestContainerActionGateOrdering(t *testing.T) {
	const body = `{"name":"nginx","action":"START"}`

	t.Run("foreign origin", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := containerRequest(t, body, "https://evil.example.com")
		p.handleContainerAction(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonOriginMismatch)
	})

	t.Run("missing session", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		r := httptest.NewRequest(http.MethodPost, "/api/docker/action", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Host = "localhost:8390"
		w := httptest.NewRecorder()
		p.handleContainerAction(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonSessionMissing)
	})

	t.Run("missing csrf header", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := containerRequest(t, body, "")
		r.Header.Del("X-CSRF-Token")
		p.handleContainerAction(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonCSRFFailed)
	})

	t.Run("wrong csrf token", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := containerRequest(t, body, "")
		r.Header.Set("X-CSRF-Token", "not-the-token")
		p.handleContainerAction(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonCSRFFailed)
	})
}

// TestContainerActionRejectsUnknownActionAndBadName asserts the closed write
// surface and the traversal/flag-name guard, both audited.
func TestContainerActionRejectsUnknownActionAndBadName(t *testing.T) {
	cases := []string{
		`{"name":"nginx","action":"REMOVE"}`,
		`{"name":"nginx","action":"rm -rf /"}`,
		`{"name":"nginx","action":"KILL"}`,
		`{"name":"../nginx","action":"START"}`,
		`{"name":"-nginx","action":"START"}`,
		`{"name":"nginx;reboot","action":"START"}`,
		`{"name":"nginx","action":"START","extra":"leak"}`,
	}
	for i, body := range cases {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		w, r := containerRequest(t, body, "")
		p.handleContainerAction(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("case %d body=%s status = %d, want 400", i, body, w.Code)
		}
		assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonContainerRequestBad)
	}
}

// TestParseDockerTargetBounds pins the log/stats parameter gate: an out-of-range
// or non-numeric line count is refused rather than silently clamped, and a bad
// name never reaches the agent.
func TestParseDockerTargetBounds(t *testing.T) {
	// valid
	r := httptest.NewRequest(http.MethodGet, "/api/docker/logs?name=nginx", nil)
	if name, lines, ok := parseDockerTarget(r); !ok || name != "nginx" || lines != maxLogLines {
		t.Fatalf("default target = (%q,%d,%v), want (nginx,%d,true)", name, lines, ok, maxLogLines)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/docker/logs?name=nginx&lines=200", nil)
	if name, lines, ok := parseDockerTarget(r); !ok || lines != 200 {
		t.Fatalf("explicit lines = (%q,%d,%v), want (nginx,200,true)", name, lines, ok)
	}
	for _, query := range []string{
		"/api/docker/logs?name=",
		"/api/docker/logs?name=../nginx",
		"/api/docker/logs?name=-nginx",
		"/api/docker/logs?name=nginx&lines=0",
		"/api/docker/logs?name=nginx&lines=-5",
		"/api/docker/logs?name=nginx&lines=501",
		"/api/docker/logs?name=nginx&lines=abc",
	} {
		if _, _, ok := parseDockerTarget(httptest.NewRequest(http.MethodGet, query, nil)); ok {
			t.Fatalf("query %q must be rejected", query)
		}
	}
}

func assertContainerAudit(t *testing.T, audit *capturedAuthAudit, wantOutcome, wantReason string) {
	t.Helper()
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Type != authaudit.TypeContainerAction || ev.Outcome != wantOutcome || ev.Reason != wantReason {
		t.Fatalf("unexpected audit event: %+v (want type=%s outcome=%s reason=%s)",
			ev, authaudit.TypeContainerAction, wantOutcome, wantReason)
	}
}

// fakeAgent installs a temporary unix socket that answers exactly one request,
// echoing the action and params it received and returning canned data. This is
// what lets the success path be tested end to end: the panel must report success
// only when the agent reports sent=true, and must have passed the target and
// action through unchanged (no smuggling, no shell).
func fakeAgent(t *testing.T, canned map[string]any) (sock string, got *fakeAgentCapture) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "agent.sock")
	cap := &fakeAgentCapture{}
	server, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var inbound struct {
			Action string         `json:"action"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(conn).Decode(&inbound); err != nil {
			return
		}
		cap.Action, cap.Params = inbound.Action, inbound.Params
		out := map[string]any{"id": "panel", "ok": true, "data": canned}
		_ = json.NewEncoder(conn).Encode(out)
	}()
	return sock, cap
}

type fakeAgentCapture struct {
	Action string
	Params map[string]any
}

// TestContainerActionSuccessPath verifies the happy path end to end: the write
// gate passes, the request is forwarded verbatim, and exactly one success audit
// entry is written.
func TestContainerActionSuccessPath(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{
		"sent": true, "name": "nginx", "action": "STOP", "state": "exited", "verified": true,
	})
	audit := &capturedAuthAudit{}
	p := &panel{
		password: "secret", attempts: map[string]int{}, authAudit: audit,
		clients: agentbridge.New(sock),
	}
	w, r := containerRequest(t, `{"name":"nginx","action":"stop"}`, "")
	p.handleContainerAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got.Action != "docker.container.action" {
		t.Fatalf("agent action = %q", got.Action)
	}
	if got.Params["name"] != "nginx" || got.Params["action"] != "STOP" {
		t.Fatalf("forwarded params = %#v, want name=nginx action=STOP", got.Params)
	}
	if len(got.Params) != 2 {
		t.Fatalf("forwarded extra params: %#v", got.Params)
	}
	assertContainerAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonContainerActionSent)
}

// TestContainerActionReportsUnsentAsFailure pins that sent=false from the agent
// is a failure, not a success — the panel must never display "已执行" for an
// operation the agent did not perform.
func TestContainerActionReportsUnsentAsFailure(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{
		"sent": false, "name": "ghost", "action": "START", "reason": "container not found",
	})
	audit := &capturedAuthAudit{}
	p := &panel{
		password: "secret", attempts: map[string]int{}, authAudit: audit,
		clients: agentbridge.New(sock),
	}
	w, r := containerRequest(t, `{"name":"ghost","action":"START"}`, "")
	p.handleContainerAction(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonContainerActionFailed)
}

// TestContainerActionKillRequiresForce asserts the hard-kill confirmation gate on
// the P2 surface, matching the process SIGKILL rule.
func TestContainerActionKillRequiresForce(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{"sent": true, "action": "KILL"})
	audit := &capturedAuthAudit{}
	p := &panel{
		password: "secret", attempts: map[string]int{}, authAudit: audit,
		clients: agentbridge.New(sock),
	}
	w, r := containerRequest(t, `{"name":"nginx","action":"KILL","force":false}`, "")
	p.handleContainerAction(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	assertContainerAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonContainerRequestBad)
}
