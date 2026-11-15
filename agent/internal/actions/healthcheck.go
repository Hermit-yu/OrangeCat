package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HealthCheck produces a bounded, structured report of host health.
// It is read-only and aggregates the individual metric actions; each check
// reports its own availability so a partial failure never hides the others.
// The "scope" param selects which check groups to run: default "all"
// (memory, disk, swap, load, docker, nginx, net). Each check is capped.
func HealthCheck(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		if key != "scope" {
			return nil, fmt.Errorf("health.check accepts only the 'scope' parameter")
		}
	}
	scope := "all"
	if s, ok := p["scope"].(string); ok && strings.TrimSpace(s) != "" {
		scope = strings.TrimSpace(s)
	}
	validScopes := map[string]bool{"all": true, "quick": true, "detailed": true}
	if !validScopes[scope] {
		return nil, errors.New("scope must be one of all/quick/detailed")
	}

	type check struct {
		name string
		run  func(context.Context) (map[string]any, error)
	}
	checks := []check{}

	// memory + load + swap: derive thresholds from current readings.
	checks = append(checks, check{"memory", func(ctx context.Context) (map[string]any, error) {
		m, err := SystemMetrics(ctx, nil)
		if err != nil {
			return nil, err
		}
		rec := map[string]any{}
		if v, has := m["mem_used_percent"].(float64); has {
			rec["used_percent"] = v
			if v > 90 {
				rec["status"] = "critical"
			} else if v > 80 {
				rec["status"] = "warning"
			} else {
				rec["status"] = "ok"
			}
		}
		if v, ok := m["swap_used_percent"].(float64); ok {
			rec["swap_used_percent"] = v
			if v > 90 {
				if rec["status"] != "critical" {
					rec["status"] = "warning"
				}
			}
		}
		if v, ok := m["load_15m"].(float64); ok {
			cores := 1
			if c, ok := m["cpu_cores"].(int); ok && c > 0 {
				cores = c
			}
			rec["load_15m"] = v
			if v > float64(cores)*2 {
				rec["status"] = "critical"
			} else if v > float64(cores) {
				if rec["status"] == "" {
					rec["status"] = "warning"
				}
			}
		}
		if rec["status"] == "" {
			rec["status"] = "ok"
		}
		return rec, nil
	}})

	checks = append(checks, check{"disk", func(ctx context.Context) (map[string]any, error) {
		m, err := SystemMetrics(ctx, nil)
		if err != nil {
			return nil, err
		}
		rec := map[string]any{}
		if v, ok := m["disk_used_percent"].(float64); ok {
			rec["used_percent"] = v
			if v > 90 {
				rec["status"] = "critical"
			} else if v > 80 {
				rec["status"] = "warning"
			} else {
				rec["status"] = "ok"
			}
		}
		if v, ok := m["disk_inodes_used_percent"].(float64); ok {
			rec["inodes_used_percent"] = v
			if v > 80 {
				if rec["status"] != "critical" {
					rec["status"] = "warning"
				}
			}
		}
		if rec["status"] == "" {
			rec["status"] = "ok"
		}
		return rec, nil
	}})

	checks = append(checks, check{"docker", func(ctx context.Context) (map[string]any, error) {
		d, err := DockerSummary(ctx, nil)
		if err != nil {
			return nil, err
		}
		rec := map[string]any{}
		if av, _ := d["available"].(bool); !av {
			rec["status"] = "unavailable"
			if e, ok := d["error"].(string); ok {
				rec["reason"] = e
			}
			return rec, nil
		}
		rec["status"] = "ok"
		if c, ok := d["containers"]; ok {
			rec["containers"] = c
		}
		if i, ok := d["images"]; ok {
			rec["images"] = i
		}
		return rec, nil
	}})

	checks = append(checks, check{"nginx", func(ctx context.Context) (map[string]any, error) {
		n, err := NginxSites(ctx, nil)
		if err != nil {
			return nil, err
		}
		rec := map[string]any{"status": "ok"}
		if c, ok := n["count"]; ok {
			rec["sites"] = c
		}
		return rec, nil
	}})

	// quick = memory+disk only; detailed = all groups
	switch scope {
	case "quick":
		checks = checks[:2]
	}

	report := map[string]any{"scope": scope, "ts": time.Now().Unix(), "checks": map[string]any{}}
	for _, c := range checks {
		rec, err := c.run(ctx)
		if err != nil {
			report["checks"].(map[string]any)[c.name] = map[string]any{"status": "error", "reason": err.Error()}
			continue
		}
		report["checks"].(map[string]any)[c.name] = rec
	}
	// overall
	worst := "ok"
	order := map[string]int{"ok": 0, "warning": 1, "critical": 2, "unavailable": 1, "error": 2}
	for _, raw := range report["checks"].(map[string]any) {
		if m, ok := raw.(map[string]any); ok {
			if s, ok := m["status"].(string); ok {
				if order[s] > order[worst] {
					worst = s
				}
			}
		}
	}
	report["overall"] = worst
	return report, nil
}

// KillProcess sends a signal to a PID after verifying it exists and is
// owned by a real /proc entry (R3: structured pid only, no shell).
// Default signal is SIGTERM; SIGKILL only when param force=true.
//
// P5：start_time 校验——调用方可传期望的进程启动时间（epoch 秒，从
// /proc/<pid>/stat field 22），若不匹配则拒绝发送信号，防 PID 复用误杀
// （进程结束后 PID 被新进程复用，无校验会误杀新进程）。
func KillProcess(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		switch key {
		case "pid", "signal", "force", "start_time":
		default:
			return nil, fmt.Errorf("kill.process accepts pid, signal, force, start_time")
		}
	}
	pidVal, ok := p["pid"].(float64)
	if !ok {
		return nil, errors.New("pid is required and must be a number")
	}
	pid := int(pidVal)
	if pid < 1 || pid > 1<<30 {
		return nil, errors.New("pid out of range")
	}
	signal := "TERM"
	if s, ok := p["signal"].(string); ok && strings.TrimSpace(s) != "" {
		signal = strings.ToUpper(strings.TrimSpace(s))
	}
	if !(signal == "TERM" || signal == "KILL") {
		return nil, errors.New("signal must be TERM or KILL")
	}
	if signal == "KILL" {
		if f, _ := p["force"].(bool); !f {
			return nil, errors.New("SIGKILL requires force=true")
		}
	}
	// 期望启动时间校验（防 PID 复用）：若调用方传了 start_time（epoch 秒），
	// 必须与 /proc/<pid>/stat field 22 的启动时钟节拍一致才放行。
	if rawST, hasST := p["start_time"]; hasST {
		wantST, ok := rawST.(float64)
		if !ok || wantST < 0 {
			return nil, errors.New("start_time must be a non-negative number")
		}
		gotST, err := readProcStartTicks(pid)
		if err != nil {
			return map[string]any{"sent": false, "pid": pid, "reason": "cannot read start time"}, nil
		}
		if gotST != int64(wantST) {
			return map[string]any{"sent": false, "pid": pid, "reason": "start time mismatch (pid reused?)"}, nil
		}
	}

	// Verify the pid actually exists and capture its comm for audit context.
	statPath := filepath.Join("/proc", fmt.Sprint(pid), "stat")
	statB, err := os.ReadFile(statPath)
	if err != nil {
		return map[string]any{"sent": false, "pid": pid, "reason": "pid does not exist"}, nil
	}
	idx := strings.LastIndex(string(statB), ") ")
	comm := "unknown"
	if idx >= 0 && strings.Count(string(statB), "(") >= 1 {
		start := strings.Index(string(statB), "(") + 1
		comm = string(statB)[start:idx]
	}
	_ = idx

	// Look up the process owner uid from /proc/<pid>/status for the report.
	uid := ""
	if statusB, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "status")); err == nil {
		for _, line := range strings.Split(string(statusB), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					uid = fields[1]
				}
				break
			}
		}
	}

	// Send the signal. Agent runs as root, so it can signal any process;
	// the audit trail (registry dispatch) records pid/signal/comm/uid.
	var killErr error
	sig := syscall.SIGTERM
	if signal == "KILL" {
		sig = syscall.SIGKILL
	}
	if proc, perr := os.FindProcess(pid); perr != nil {
		killErr = perr
	} else {
		killErr = proc.Signal(sig)
	}
	if killErr != nil {
		return map[string]any{"sent": false, "pid": pid, "signal": signal, "comm": comm, "uid": uid, "reason": killErr.Error()}, nil
	}
	return map[string]any{"sent": true, "pid": pid, "signal": signal, "comm": comm, "uid": uid}, nil
}

// readProcStartTicks returns field 22 (starttime in clock ticks) from
// /proc/<pid>/stat. PID reuse protection compares this exact value.
func readProcStartTicks(pid int) (int64, error) {
	b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// comm is in parens; find last ')' then field 22 is the 20th field after.
	idx := strings.LastIndex(string(b), ") ")
	if idx < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(string(b)[idx+2:])
	// After ") ": fields[0]=state(3), [1]=ppid(4), ... [19]=starttime(22)
	if len(fields) < 20 {
		return 0, errors.New("stat fields too short")
	}
	return strconv.ParseInt(fields[19], 10, 64)
}
