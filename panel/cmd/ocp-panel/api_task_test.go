package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
)

func TestTaskStartRelaysAgent(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{"task_id": "t1", "state": "running"})
	p := &panel{password: "secret", attempts: map[string]int{}, clients: agentbridge.New(sock)}
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodPost, "/api/task/start", strings.NewReader("type=hostdiag"))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleTaskStart(w, r)
	if got.Action != "task.start" {
		t.Fatalf("agent action = %q", got.Action)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["ok"] != true {
		t.Fatalf("ok = false body=%s", w.Body.String())
	}
}

func TestTaskStatusReadsQuery(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{"task_id": "t2", "state": "done"})
	p := &panel{password: "secret", attempts: map[string]int{}, clients: agentbridge.New(sock)}
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodGet, "/api/task/status?task_id=t2", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleTaskStatus(w, r)
	if got.Action != "task.status" {
		t.Fatalf("agent action = %q", got.Action)
	}
}

func TestTaskLogRequiresTaskID(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{})
	p := &panel{password: "secret", attempts: map[string]int{}, clients: agentbridge.New(sock)}
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodGet, "/api/task/log", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleTaskLog(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing task_id accepted: %d", w.Code)
	}
}
