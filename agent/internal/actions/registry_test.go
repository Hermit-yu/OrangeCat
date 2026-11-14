package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/agent/internal/audit"
)

func startSocketTestServer(t *testing.T, reg *Registry, configure func(*SocketServer)) (*SocketServer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.sock")
	server := reg.Serve()
	if configure != nil {
		configure(server)
	}
	if err := server.Start(path, audit.New(filepath.Join(t.TempDir(), "agent-audit.jsonl"))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, path
}

func TestSocketServerRejectsOversizedRequestBeforeDispatch(t *testing.T) {
	var dispatched atomic.Int32
	reg := &Registry{handlers: map[string]Handler{
		"test.echo": func(context.Context, map[string]any) (map[string]any, error) {
			dispatched.Add(1)
			return map[string]any{"ok": true}, nil
		},
	}}
	_, path := startSocketTestServer(t, reg, func(s *SocketServer) { s.maxRequestBytes = 96 })
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, `{"id":"x","action":"test.echo","params":{"value":"`+strings.Repeat("x", 256)+`"}}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("read bounded rejection: %v", err)
	}
	if response.OK {
		t.Fatalf("oversized request dispatched successfully: %+v", response)
	}
	if got := dispatched.Load(); got != 0 {
		t.Fatalf("handler called %d times for oversized request", got)
	}
}

func TestSocketServerCapsResponseBytes(t *testing.T) {
	reg := &Registry{handlers: map[string]Handler{
		"test.large": func(context.Context, map[string]any) (map[string]any, error) {
			return map[string]any{"payload": strings.Repeat("x", 2048)}, nil
		},
	}}
	_, path := startSocketTestServer(t, reg, func(s *SocketServer) { s.maxResponseBytes = 256 })
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, `{"id":"x","action":"test.large"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read bounded response: %v", err)
	}
	if len(line) > 256 {
		t.Fatalf("response line has %d bytes, exceeds 256", len(line))
	}
	var response Response
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	if response.OK {
		t.Fatalf("oversized action response was returned as success: %+v", response)
	}
}

func TestSocketServerTimesOutIdleConnections(t *testing.T) {
	reg := &Registry{handlers: map[string]Handler{}}
	_, path := startSocketTestServer(t, reg, func(s *SocketServer) { s.requestTimeout = 40 * time.Millisecond })
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, err := conn.Read(one); err == nil {
		t.Fatal("idle socket returned unexpected data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("idle connection was not closed before client deadline: %v", err)
	}
}

func TestSocketServerCancelsActionAtDeadline(t *testing.T) {
	started := make(chan struct{})
	reg := &Registry{handlers: map[string]Handler{
		"test.wait": func(ctx context.Context, _ map[string]any) (map[string]any, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}}
	_, path := startSocketTestServer(t, reg, func(s *SocketServer) { s.requestTimeout = 40 * time.Millisecond })
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, `{"id":"wait","action":"test.wait"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("action handler did not start")
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("read action timeout response: %v", err)
	}
	if response.OK || !strings.Contains(response.Error, "deadline exceeded") {
		t.Fatalf("action timeout response = %+v", response)
	}
}

func TestSocketServerDoesNotPersistUntrustedRequestParametersInAudit(t *testing.T) {
	dir, err := os.MkdirTemp("", "ocp-audit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "a.sock")
	auditPath := filepath.Join(dir, "agent-audit.jsonl")
	reg := &Registry{handlers: map[string]Handler{
		"test.fail": func(context.Context, map[string]any) (map[string]any, error) {
			return nil, errors.New("fixed failure")
		},
	}}
	server := reg.Serve()
	if err := server.Start(socketPath, audit.New(auditPath)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, `{"id":"x","action":"test.fail","params":{"password":"never-store-this"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	records, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(records), "never-store-this") || strings.Contains(string(records), `"password"`) {
		t.Fatalf("audit contains raw request parameters: %s", records)
	}
}

func TestSocketServerRejectsNonSocketPathAndPreservesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	server := (&Registry{handlers: map[string]Handler{}}).Serve()
	if err := server.Start(path, nil); err == nil {
		_ = server.Close()
		t.Fatal("Start accepted a symlink path")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve" {
		t.Fatalf("target changed: %q", got)
	}
}

func TestSocketServerUsesGroupConnectPermissions(t *testing.T) {
	_, path := startSocketTestServer(t, &Registry{handlers: map[string]Handler{}}, nil)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf("socket mode = %04o, want 0660", got)
	}
}

func TestSocketServerLimitsConcurrentConnections(t *testing.T) {
	_, path := startSocketTestServer(t, &Registry{handlers: map[string]Handler{}}, func(s *SocketServer) {
		s.maxConnections = 1
		s.requestTimeout = time.Second
	})
	first, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(first, `{}`+"\n"); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(first).Decode(&response); err != nil {
		t.Fatalf("first connection not served: %v", err)
	}

	second, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("connection over concurrency limit was not closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection over concurrency limit remained open: %v", err)
	}
}

func TestSocketServerRejectsSymlinkedParentDirectory(t *testing.T) {
	realDir := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	server := (&Registry{handlers: map[string]Handler{}}).Serve()
	if err := server.Start(filepath.Join(linkDir, "agent.sock"), nil); err == nil {
		_ = server.Close()
		t.Fatal("Start accepted a symlinked parent directory")
	}
}
