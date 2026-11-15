package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
)

// fsRequest builds a session-authorized GET for the P4 read-only endpoints.
func fsRequest(t *testing.T, target string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	token, _ := seededSession(t)
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	return httptest.NewRecorder(), r
}

func TestFsEndpointsRequireGetAndPath(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}

	// POST is refused before any path handling.
	for _, path := range []string{"/api/fs/list", "/api/fs/read", "/api/fs/stat"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Host = "localhost:8390"
		w := httptest.NewRecorder()
		switch path {
		case "/api/fs/list":
			p.handleFsList(w, r)
		case "/api/fs/read":
			p.handleFsRead(w, r)
		case "/api/fs/stat":
			p.handleFsStat(w, r)
		}
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s POST status = %d, want 405", path, w.Code)
		}
	}

	// Missing path is a 400 from the handler itself.
	for _, path := range []string{"/api/fs/list", "/api/fs/read", "/api/fs/stat"} {
		_, r := fsRequest(t, path)
		w := httptest.NewRecorder()
		switch path {
		case "/api/fs/list":
			p.handleFsList(w, r)
		case "/api/fs/read":
			p.handleFsRead(w, r)
		case "/api/fs/stat":
			p.handleFsStat(w, r)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s without path status = %d, want 400", path, w.Code)
		}
	}
}

func TestFsListSuccessAndAgentRelay(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{
		"path": "/home/web", "count": 2, "truncated": false,
		"entries": []map[string]any{
			{"name": "conf.d", "type": "dir", "size": 0},
			{"name": "acme.sh", "type": "file", "size": 0},
		},
	})
	p := &panel{password: "secret", attempts: map[string]int{}, clients: agentbridge.New(sock)}
	_, r := fsRequest(t, "/api/fs/list?path=/home/web")
	w := httptest.NewRecorder()
	p.handleFsList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got.Action != "fs.list" {
		t.Fatalf("agent action = %q, want fs.list", got.Action)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	list, _ := out["list"].(map[string]any)
	if entries, _ := list["entries"].([]any); len(entries) != 2 {
		t.Fatalf("entries = %v, want 2", list["entries"])
	}
}

func TestFsReadStatRelayAgentAction(t *testing.T) {
	for _, c := range []struct {
		target string
		want   string
		call   func(*panel, http.ResponseWriter, *http.Request)
	}{
		{"/api/fs/read?path=/home/web/conf.d/x.conf", "fs.read", func(pp *panel, w http.ResponseWriter, r *http.Request) { pp.handleFsRead(w, r) }},
		{"/api/fs/stat?path=/home/web/conf.d/x.conf", "fs.stat", func(pp *panel, w http.ResponseWriter, r *http.Request) { pp.handleFsStat(w, r) }},
	} {
		sock, got := fakeAgent(t, map[string]any{"path": c.target, "content": "ok"})
		pp := &panel{password: "secret", attempts: map[string]int{}, clients: agentbridge.New(sock)}
		_, r := fsRequest(t, c.target)
		w := httptest.NewRecorder()
		c.call(pp, w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d", c.want, w.Code)
		}
		if got.Action != c.want {
			t.Fatalf("agent action = %q, want %s", got.Action, c.want)
		}
	}
}
