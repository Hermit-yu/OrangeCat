package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit appends action records to a bounded JSONL file.
type Audit struct {
	mu   sync.Mutex
	f    *os.File
	path string
	maxLines int
}

func New(path string) *Audit {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		f, err = os.CreateTemp("", "ocp-audit-*") // last resort so audit never blocks
		_ = f.Close()
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	}
	return &Audit{f: f, path: path, maxLines: 10000}
}

func (a *Audit) Record(action string, params map[string]any, ok bool, errMsg string, durMs int64) {
	if a == nil || a.f == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := map[string]any{
		"ts": time.Now().Format(time.RFC3339),
		"action": action,
		"params": params,
		"ok": ok,
		"dur_ms": durMs,
	}
	if errMsg != "" {
		rec["error"] = errMsg
	}
	b, _ := json.Marshal(rec)
	b = append(b, '\n')
	a.f.Write(b)
	// Rotate: keep file bounded
	if countLines(a.path) > a.maxLines {
		rotate := a.path + ".old"
		a.f.Close()
		os.Rename(a.path, rotate)
		f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			a.f = f
		} else {
			a.f = nil
		}
	}
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	buf := make([]byte, 4096)
	for {
		r, _ := f.Read(buf)
		if r == 0 {
			break
		}
		for i := 0; i < r; i++ {
			if buf[i] == '\n' {
				n++
			}
		}
	}
	return n
}
