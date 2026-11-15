package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// seededSession creates a panel with one valid session and returns the cookie
// values needed to authenticate a request.
func seededSession(t *testing.T) (string, string) {
	t.Helper()
	token := "sess-token-value"
	csrf := "csrf-token-value"
	addSession(token, session{token: token, csrf: csrf, created: time.Now()}, time.Now())
	t.Cleanup(func() { deleteSession(token) })
	return token, csrf
}

func TestParseRangeDefaults(t *testing.T) {
	now := int64(1000000)
	r := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	from, to, err := parseRange(r, now)
	if err != nil {
		t.Fatalf("default range returned error: %v", err)
	}
	if to != now {
		t.Fatalf("default to = %d, want %d", to, now)
	}
	if from != now-3600 {
		t.Fatalf("default from = %d, want %d", from, now-3600)
	}
	// explicit valid range passes through unchanged
	r = httptest.NewRequest(http.MethodGet, "/api/history?from=500&to=900", nil)
	from, to, err = parseRange(r, now)
	if err != nil {
		t.Fatalf("explicit range returned error: %v", err)
	}
	if from != 500 || to != 900 {
		t.Fatalf("explicit range: from=%d to=%d", from, to)
	}
}

// 非法或超窗口的范围必须被拒绝，而不是静默降级成默认值 ——
// 否则 from=0 可以扫全库，非数字参数也会被当成"用户想要最近 1 小时"。
func TestParseRangeRejectsBadInput(t *testing.T) {
	now := int64(1000000)
	cases := []string{
		"/api/history?from=abc",
		"/api/history?to=xyz",
		"/api/history?from=900&to=500", // inverted
		"/api/history?from=-1",
		"/api/history?from=0&to=1000000000", // oversized span (> 366 days)
	}
	for _, target := range cases {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if _, _, err := parseRange(r, now); err == nil {
			t.Fatalf("range %s should be rejected", target)
		}
	}
}

func TestHistoryRejectsUnknownLevel(t *testing.T) {
	token, _ := seededSession(t)
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodGet, "/api/history?level=bogus", nil)
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()
	p.requireAuth(p.handleHistory).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", w.Code, w.Body.String())
	}
}

func TestProcessKillRequiresPost(t *testing.T) {
	token, _ := seededSession(t)
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodGet, "/api/processes/kill", nil)
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestProcessKillRequiresSession(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":1}`))
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestProcessKillRejectsMissingCSRF(t *testing.T) {
	token, _ := seededSession(t)
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":1}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", w.Code, w.Body.String())
	}
}

func TestProcessKillRejectsWrongCSRF(t *testing.T) {
	token, _ := seededSession(t)
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":1}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: "csrf-token-value"})
	r.Header.Set("X-CSRF-Token", "wrong-token")
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestProcessKillRejectsForeignOrigin(t *testing.T) {
	token, csrf := seededSession(t)
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":1}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", w.Code, w.Body.String())
	}
}

func TestProcessKillRecordsUnknownFieldsRejected(t *testing.T) {
	token, csrf := seededSession(t)
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
	body := `{"pid":1,"path":"/etc/passwd"}`
	r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleProcessKill(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", w.Code, w.Body.String())
	}
}

// 进程结束是写操作，每个出口都必须留审计痕。这里锁住两处：
// 请求体非法（400）与 PID 1 拒绝（403）都要各写一条，否则失败操作会无痕。
func TestProcessKillAuditLeavesTrailOnRejections(t *testing.T) {
	token, csrf := seededSession(t)

	t.Run("invalid request body", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":0}`))
		r.RemoteAddr = "192.0.2.77:1234"
		r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
		r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		p.handleProcessKill(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		assertKillAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonKillRequestInvalid, "192.0.2.77")
	})

	t.Run("pid 1 init is forbidden", func(t *testing.T) {
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
		r := httptest.NewRequest(http.MethodPost, "/api/processes/kill", strings.NewReader(`{"pid":1,"signal":"TERM"}`))
		r.RemoteAddr = "192.0.2.78:1234"
		r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
		r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		p.handleProcessKill(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		assertKillAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonKillPIDInitForbidden, "192.0.2.78")
	})
}

// 审计事件只允许写 pid 级别的固定分类，绝不落 token、csrf、cookie 或凭据。
func assertKillAudit(t *testing.T, audit *capturedAuthAudit, wantOutcome, wantReason, wantIP string) {
	t.Helper()
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Type != authaudit.TypeProcessKill || ev.Outcome != wantOutcome || ev.Reason != wantReason || ev.ClientIP != wantIP {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "csrf", "cookie", "secret", "password"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Errorf("kill audit contains forbidden value/field %q: %s", forbidden, encoded)
		}
	}
}
