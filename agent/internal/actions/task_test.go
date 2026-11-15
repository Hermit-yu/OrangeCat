package actions

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTaskStartRunsAsyncAndCompletes(t *testing.T) {
	resetTaskRegistry()
	ctx := context.Background()
	got, err := TaskStart(ctx, map[string]any{"type": "hostdiag"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	id, _ := got["task_id"].(string)
	if id == "" {
		t.Fatal("no task_id")
	}
	if st, _ := got["state"].(string); st != "running" {
		t.Fatalf("initial state = %q", st)
	}
	// poll until done (bounded).
	var final map[string]any
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		s, err := TaskStatus(ctx, map[string]any{"task_id": id})
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if s["state"] == "done" || s["state"] == "failed" {
			final = s
			break
		}
	}
	if final == nil {
		t.Fatal("task never completed")
	}
	if final["state"] != "done" {
		t.Fatalf("final state = %v err=%v", final["state"], final["error"])
	}
	res, _ := final["result"].(map[string]any)
	if res == nil {
		t.Fatal("no result")
	}
	if _, ok := res["hostname"].(string); !ok {
		t.Fatalf("result missing hostname: %v", res)
	}
}

func TestTaskStatusUnknown(t *testing.T) {
	resetTaskRegistry()
	_, err := TaskStatus(context.Background(), map[string]any{"task_id": "no-such"})
	if err == nil {
		t.Fatal("unknown task accepted")
	}
}

func TestTaskStartUnknownType(t *testing.T) {
	resetTaskRegistry()
	_, err := TaskStart(context.Background(), map[string]any{"type": "rm -rf /"})
	if err == nil {
		t.Fatal("unknown task type accepted")
	}
}

func TestTaskLogBounded(t *testing.T) {
	resetTaskRegistry()
	ctx := context.Background()
	got, _ := TaskStart(ctx, map[string]any{"type": "hostdiag"})
	id, _ := got["task_id"].(string)
	// wait for done
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		s, _ := TaskStatus(ctx, map[string]any{"task_id": id})
		if s["state"] == "done" {
			break
		}
	}
	logs, err := TaskLog(ctx, map[string]any{"task_id": id})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	lines, _ := logs["lines"].([]string)
	if len(lines) == 0 {
		t.Fatal("no log lines")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "hostdiag") {
		t.Fatalf("log missing type marker: %q", joined)
	}
}
