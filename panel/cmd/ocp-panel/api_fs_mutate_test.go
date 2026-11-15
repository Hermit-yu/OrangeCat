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

func fsMutateReq(t *testing.T, p *panel, target, body string) *httptest.ResponseRecorder {
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
	case "/api/fs/rename":
		p.handleFsRename(w, r)
	case "/api/fs/remove":
		p.handleFsRemove(w, r)
	case "/api/fs/restore":
		p.handleFsRestore(w, r)
	default:
		t.Fatalf("unhandled target %s", target)
	}
	return w
}

func assertFsMutateAudit(t *testing.T, audit *capturedAuthAudit, wantOutcome, wantReason string) {
	t.Helper()
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Type != authaudit.TypeFsMutate || ev.Outcome != wantOutcome || ev.Reason != wantReason {
		t.Fatalf("unexpected audit event: %+v (want type=%s outcome=%s reason=%s)",
			ev, authaudit.TypeFsMutate, wantOutcome, wantReason)
	}
}

func TestFsRenameSuccessAndAudit(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{"ok": true, "path": "/tmp/new.txt"})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	w := fsMutateReq(t, p, "/api/fs/rename", `{"path":"/tmp/old.txt","new_path":"/tmp/new.txt"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got.Action != "fs.rename" || got.Params["new_path"] != "/tmp/new.txt" {
		t.Fatalf("relay mismatch: %s %v", got.Action, got.Params)
	}
	assertFsMutateAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonFsRenameSent)
}

func TestFsRemoveRequiresForce(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	// No force → rejected before agent call.
	w := fsMutateReq(t, p, "/api/fs/remove", `{"path":"/tmp/a.txt"}`)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["ok"] != false {
		t.Fatalf("expected ok=false without force, got %s", w.Body.String())
	}
	assertFsMutateAudit(t, audit, authaudit.OutcomeRejected, authaudit.ReasonFsRemoveRequestBad)
}

func TestFsRemoveSuccessAndAudit(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{
		"ok": true, "path": "/tmp/a.txt", "removed": "file",
		"snapshot": "/var/lib/ocp/fs-snapshots/123.snap",
	})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	w := fsMutateReq(t, p, "/api/fs/remove", `{"path":"/tmp/a.txt","force":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got.Action != "fs.remove" {
		t.Fatalf("agent action = %q", got.Action)
	}
	assertFsMutateAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonFsRemoveSent)
}

func TestFsRestoreFileAndDir(t *testing.T) {
	for _, c := range []struct {
		body string
		want string
		dir  bool
	}{
		{`{"path":"/tmp/a.txt","snapshot":"/var/lib/ocp/fs-snapshots/1.snap"}`, "fs.restore", false},
		{`{"path":"/tmp/emptydir","dir":true}`, "fs.restore", true},
	} {
		sock, got := fakeAgent(t, map[string]any{"ok": true, "path": "/tmp/x"})
		audit := &capturedAuthAudit{}
		p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
		w := fsMutateReq(t, p, "/api/fs/restore", c.body)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
		}
		if got.Action != c.want {
			t.Fatalf("agent action = %q, want %s", got.Action, c.want)
		}
		if c.dir && got.Params["dir"] != true {
			t.Fatalf("dir flag not relayed: %v", got.Params)
		}
		if !c.dir && got.Params["snapshot"] == nil {
			t.Fatalf("snapshot not relayed: %v", got.Params)
		}
		assertFsMutateAudit(t, audit, authaudit.OutcomeSuccess, authaudit.ReasonFsRestoreSent)
	}
}

func TestFsMutateRejectsBadOrigin(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: &capturedAuthAudit{}}
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/fs/rename", strings.NewReader(`{"path":"/a","new_path":"/b"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://evil.example")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleFsRename(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want 403", w.Code)
	}
}
