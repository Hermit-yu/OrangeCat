package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

type capturedAuthAudit struct {
	events []authaudit.Event
	err    error
}

func (a *capturedAuthAudit) Record(event authaudit.Event) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, event)
	return nil
}

func TestLoginAuditRecordsFailureWithoutCredentials(t *testing.T) {
	audit := &capturedAuthAudit{}
	p := &panel{password: "private-password", attempts: map[string]int{}, authAudit: audit}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"private-password-wrong"}`))
	r.RemoteAddr = "192.0.2.41:443"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != authaudit.TypeLogin || event.Outcome != authaudit.OutcomeRejected || event.Reason != "bad_credentials" || event.ClientIP != "192.0.2.41" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-password", "username", "password", "session", "csrf", "token"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Errorf("audit event contains forbidden value/field %q: %s", forbidden, encoded)
		}
	}
}

func TestLoginFailsClosedWhenSuccessAuditCannotBeWritten(t *testing.T) {
	audit := &capturedAuthAudit{err: errors.New("disk unavailable")}
	p := &panel{password: "private-password", attempts: map[string]int{}, authAudit: audit}
	before := sessionCountForTest()
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"private-password"}`))
	r.RemoteAddr = "192.0.2.42:443"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("login issued cookies despite failed audit write: %d", len(cookies))
	}
	if got := sessionCountForTest(); got != before {
		t.Fatalf("session count changed from %d to %d after audit failure", before, got)
	}
}

func sessionCountForTest() int {
	sessMu.Lock()
	defer sessMu.Unlock()
	return len(sessions)
}

func TestLoginAuditRecordsSuccessWithoutCredentials(t *testing.T) {
	audit := &capturedAuthAudit{}
	p := &panel{password: "private-password", attempts: map[string]int{}, authAudit: audit}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"private-password"}`))
	r.RemoteAddr = "192.0.2.43:443"
	w := httptest.NewRecorder()
	p.handleLogin(w, r)
	t.Cleanup(func() {
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == "ocp_session" {
				deleteSession(cookie.Value)
			}
		}
	})
	if w.Code != http.StatusOK || len(audit.events) != 1 {
		t.Fatalf("status=%d audit events=%d, want 200 and one event", w.Code, len(audit.events))
	}
	event := audit.events[0]
	if event.Type != authaudit.TypeLogin || event.Outcome != authaudit.OutcomeSuccess || event.Reason != "credentials_accepted" {
		t.Fatalf("unexpected login success event: %+v", event)
	}
	encoded, _ := json.Marshal(event)
	for _, forbidden := range []string{"private-password", "username", "password", "session", "csrf", "token"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Errorf("audit event contains forbidden field/value %q", forbidden)
		}
	}
}

func TestLogoutAuditFailureDoesNotRevokeSession(t *testing.T) {
	const token = "audit-failure-session-token"
	const csrf = "audit-failure-csrf-token"
	now := time.Now()
	addSession(token, session{token: token, csrf: csrf, created: now}, now)
	t.Cleanup(func() { deleteSession(token) })
	p := &panel{authAudit: &capturedAuthAudit{err: errors.New("disk unavailable")}}
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleLogout(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if _, ok := lookupSession(token, now); !ok {
		t.Fatal("session was revoked although success audit could not be written")
	}
}
