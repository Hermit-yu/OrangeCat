package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// siteRequest builds a fully-authorized POST for the P6 site-change endpoints.
func siteRequest(t *testing.T, target, body, origin string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
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

// TestNginxSiteGateOrdering exercises all three write gates on the P6 surface.
// The success path (reaching the agent) is not unit-tested here because
// p.clients is a real unix-socket bridge; the gate rejection paths are what
// must be fail-closed without touching the agent.
func TestNginxSiteGateOrdering(t *testing.T) {
	const body = `{"file":"/home/web/conf.d/demo.taoque.top.conf","server_name":"demo.taoque.top","proxy_pass":"http://172.18.0.1:8390","mode":"create"}`

	handlers := map[string]func(*panel, http.ResponseWriter, *http.Request){
		"/api/nginx/site/validate": func(p *panel, w http.ResponseWriter, r *http.Request) { p.handleNginxSiteValidate(w, r) },
		"/api/nginx/site/save":     func(p *panel, w http.ResponseWriter, r *http.Request) { p.handleNginxSiteSave(w, r) },
		"/api/nginx/site/delete":   func(p *panel, w http.ResponseWriter, r *http.Request) { p.handleNginxSiteDelete(w, r) },
	}

	for target, h := range handlers {
		t.Run(target+" foreign origin", func(t *testing.T) {
			audit := &capturedAuthAudit{}
			p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
			w, r := siteRequest(t, target, body, "https://evil.example.com")
			h(p, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if len(audit.events) != 1 || audit.events[0].Reason != authaudit.ReasonOriginMismatch {
				t.Fatalf("unexpected audit: %+v", audit.events)
			}
		})
		t.Run(target+" missing session", func(t *testing.T) {
			audit := &capturedAuthAudit{}
			p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			r.RemoteAddr = "127.0.0.1:1234"
			r.Host = "localhost:8390"
			w := httptest.NewRecorder()
			h(p, w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
		t.Run(target+" missing csrf header", func(t *testing.T) {
			audit := &capturedAuthAudit{}
			p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
			w, r := siteRequest(t, target, body, "")
			r.Header.Del("X-CSRF-Token")
			h(p, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if len(audit.events) != 1 || audit.events[0].Reason != authaudit.ReasonCSRFFailed {
				t.Fatalf("unexpected audit: %+v", audit.events)
			}
		})
	}
}

// TestNginxSiteRejectsUnknownFields pins the closed write surface: an extra
// field in the body must be rejected (agent would also reject, but the panel
// layer for delete uses DisallowUnknownFields).
func TestNginxSiteRejectsUnknownFields(t *testing.T) {
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit}
	w, r := siteRequest(t, "/api/nginx/site/delete", `{"file":"/home/web/conf.d/x.conf","extra":"leak"}`, "")
	p.handleNginxSiteDelete(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if len(audit.events) != 1 || audit.events[0].Reason != authaudit.ReasonNginxRequestBad {
		t.Fatalf("unexpected audit: %+v", audit.events)
	}
}

// TestNginxSiteRequiresPost guards against a GET smuggle on all three endpoints.
func TestNginxSiteRequiresPost(t *testing.T) {
	for _, target := range []string{"/api/nginx/site/validate", "/api/nginx/site/save", "/api/nginx/site/delete"} {
		p := &panel{password: "secret", attempts: map[string]int{}}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		switch target {
		case "/api/nginx/site/validate":
			p.handleNginxSiteValidate(w, r)
		case "/api/nginx/site/save":
			p.handleNginxSiteSave(w, r)
		case "/api/nginx/site/delete":
			p.handleNginxSiteDelete(w, r)
		}
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want 405", target, w.Code)
		}
	}
}
