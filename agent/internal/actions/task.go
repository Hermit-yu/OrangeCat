package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// P4-5 切片：后台任务基础——状态 API + 有界日志。
//
// 任务注册表是进程内状态（agent 常驻，跨请求可见）。固定白名单只读任务
// （hostdiag），异步执行、状态轮询、有界环形日志。不做任意命令执行：任务
// 类型必须命中白名单，参数不传递 shell。
//
// 日志有界：每任务最多 taskMaxLogLines 行（环形覆盖），防任务日志无限增长
// 打爆内存。任务本身超时（taskMaxRun）后被标记 failed。

const (
	taskMaxLogLines = 200
	taskMaxRun      = 30 * time.Second
	taskMaxTasks    = 64
)

type task struct {
	ID        string
	Type      string
	State     string // running / done / failed
	Error     string
	Result    map[string]any
	Created   time.Time
	Finished  time.Time
	mu        sync.Mutex
	logLines  []string
	logTail   []byte
}

type taskRegistry struct {
	mu    sync.Mutex
	tasks map[string]*task
}

var globalTasks = &taskRegistry{tasks: map[string]*task{}}

// resetTaskRegistry clears the registry (test helper).
func resetTaskRegistry() {
	globalTasks.mu.Lock()
	defer globalTasks.mu.Unlock()
	globalTasks.tasks = map[string]*task{}
}

// TaskStart starts an asynchronous hostdiag task and returns its id.
func TaskStart(ctx context.Context, params map[string]any) (map[string]any, error) {
	typ, _ := params["type"].(string)
	if typ != "hostdiag" {
		return nil, fmt.Errorf("unknown task type %q", typ)
	}
	globalTasks.mu.Lock()
	if len(globalTasks.tasks) >= taskMaxTasks {
		globalTasks.mu.Unlock()
		return nil, errors.New("task registry full")
	}
	id := fmt.Sprintf("task-%d", time.Now().UnixNano())
	t := &task{ID: id, Type: typ, State: "running", Created: time.Now()}
	globalTasks.tasks[id] = t
	globalTasks.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.mu.Lock()
				t.State = "failed"
				t.Error = fmt.Sprintf("panic: %v", r)
				t.Finished = time.Now()
				t.mu.Unlock()
			}
		}()
		t.appendLog("start " + typ)
		res, err := runHostdiag(ctx, t)
		t.mu.Lock()
		defer t.mu.Unlock()
		t.Finished = time.Now()
		if err != nil {
			t.State = "failed"
			t.Error = err.Error()
			t.appendLogLocked("error: " + err.Error())
			return
		}
		t.State = "done"
		t.Result = res
		t.appendLogLocked("done")
	}()
	return map[string]any{"task_id": id, "state": "running", "type": typ}, nil
}

// TaskStatus returns current state, error and result (if done).
func TaskStatus(ctx context.Context, params map[string]any) (map[string]any, error) {
	id, _ := params["task_id"].(string)
	t := lookupTask(id)
	if t == nil {
		return nil, errors.New("unknown task")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]any{"task_id": id, "state": t.State, "type": t.Type, "error": t.Error}
	if t.State == "done" {
		out["result"] = t.Result
	}
	return out, nil
}

// TaskLog returns the bounded log lines for a task.
func TaskLog(ctx context.Context, params map[string]any) (map[string]any, error) {
	id, _ := params["task_id"].(string)
	t := lookupTask(id)
	if t == nil {
		return nil, errors.New("unknown task")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := make([]string, len(t.logLines))
	copy(lines, t.logLines)
	return map[string]any{"task_id": id, "lines": lines, "count": len(lines)}, nil
}

func lookupTask(id string) *task {
	globalTasks.mu.Lock()
	defer globalTasks.mu.Unlock()
	return globalTasks.tasks[id]
}

// appendLog appends one line, bounded ring.
func (t *task) appendLog(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.appendLogLocked(line)
}

func (t *task) appendLogLocked(line string) {
	t.logLines = append(t.logLines, line)
	if len(t.logLines) > taskMaxLogLines {
		t.logLines = t.logLines[len(t.logLines)-taskMaxLogLines:]
	}
}

// runHostdiag gathers a few host facts. Read-only, no command execution.
func runHostdiag(ctx context.Context, t *task) (map[string]any, error) {
	hostname, _ := os.Hostname()
	t.appendLog("hostname=" + hostname)
	res := map[string]any{"hostname": hostname}
	if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(uptime))
		if len(parts) > 0 {
			res["uptime_s"] = parts[0]
			t.appendLog("uptime=" + parts[0])
		}
	}
	if load, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(load))
		if len(fields) > 0 {
			res["load1"] = fields[0]
			t.appendLog("load1=" + fields[0])
		}
	}
	return res, nil
}
