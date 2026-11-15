package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBackupRequiresPost guards backup endpoints against GET smuggle.
func TestBackupRequiresPost(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	for _, target := range []string{"/api/backup/create", "/api/backup/restore"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		switch target {
		case "/api/backup/create":
			p.handleBackupCreate(w, r)
		case "/api/backup/restore":
			p.handleBackupRestore(w, r)
		}
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want 405", target, w.Code)
		}
	}
}

// TestBackupGateOrdering exercises the write gate on backup create/restore.
func TestBackupGateOrdering(t *testing.T) {
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}

	// foreign origin -> 403
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/backup/create", strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	p.handleBackupCreate(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// TestBackupRestoreRejectsBadName ensures a path traversal / wrong prefix is
// rejected before touching the filesystem.
func TestBackupRestoreRejectsBadName(t *testing.T) {
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
	for _, bad := range []string{"../../etc/passwd", "metrics-../etc", "evil.db", ""} {
		token, csrf := seededSession(t)
		r := httptest.NewRequest(http.MethodPost, "/api/backup/restore", strings.NewReader(`{"file":"`+bad+`"}`))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Host = "localhost:8390"
		r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
		r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", "http://localhost:8390")
		w := httptest.NewRecorder()
		p.handleBackupRestore(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("file=%q status = %d, want 400", bad, w.Code)
		}
	}
}
