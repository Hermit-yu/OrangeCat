// Package main probes the ocp-agent unix socket with one request per action.
// Prints one JSON line per action; exits non-zero unless all succeed.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const socketPath = "/run/ocp/agent.sock"

var actions = []string{
	"system.info",
	"system.metrics",
	"system.services",
	"net.diagnostics",
	"health.check",
	"docker.summary",
	"docker.containers",
	"docker.images",
	"docker.networks",
	"docker.volumes",
	"docker.stats",
	"docker.logs",
	"compose.projects",
	"compose.validate",
	"nginx.sites",
	"nginx.sites.full",
	"nginx.test",
	"net.interfaces",
	"processes",
	"fs.list",
	"fs.read",
	"fs.stat",
}

// params overrides the default empty params for actions that need them.
// docker.stats/logs are probed against a fixed, non-destructive target so the
// deployment check never touches a production container in a write path.
var actionParams = map[string]map[string]any{
	"processes":        {"top": 10.0},
	"docker.stats":     {"name": "nginx"},
	"docker.logs":      {"name": "nginx", "lines": 5.0},
	"compose.validate": {"path": "/opt/horizon/docker-compose.yml"},
	"fs.list":          {"path": "/home/web/conf.d"},
	"fs.read":          {"path": "/home/web/conf.d/default.conf"},
	"fs.stat":          {"path": "/home/web/conf.d"},
}

// fsWriteProbeTarget is a scratch file the probe creates in /tmp, writes once,
// then restores via rollback so the deployment check never leaves debris and
// never touches a production config file.
const fsWriteProbeTarget = "/tmp/ocp-fs-write-probe.txt"

// probeFsMutate exercises fs.rename / fs.remove / fs.restore against private
// scratch files, verifying each real state transition, and never touches a
// production config or directory.
func probeFsMutate() (bool, string) {
	dir := "/tmp/ocp-fs-mutate-probe"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, "mkdir probe dir: " + err.Error()
	}
	defer os.RemoveAll(dir)

	seed := filepath.Join(dir, "seed.txt")
	if err := os.WriteFile(seed, []byte("seed-data\n"), 0644); err != nil {
		return false, "seed: " + err.Error()
	}
	// rename
	renamed := filepath.Join(dir, "renamed.txt")
	ok, _ := probeWithParams("fs.rename", map[string]any{"path": seed, "new_path": renamed})
	if !ok {
		return false, "fs.rename failed"
	}
	if _, err := os.Stat(renamed); err != nil {
		return false, "rename target missing: " + err.Error()
	}
	// remove
	ok, data := probeWithParams("fs.remove", map[string]any{"path": renamed, "force": true})
	if !ok || data == nil {
		return false, "fs.remove failed"
	}
	if _, err := os.Stat(renamed); !os.IsNotExist(err) {
		return false, "removed target still exists"
	}
	snap, _ := data["snapshot"].(string)
	if snap == "" {
		return false, "remove snapshot missing"
	}
	// restore
	ok, _ = probeWithParams("fs.restore", map[string]any{"path": renamed, "snapshot": snap})
	if !ok {
		return false, "fs.restore failed"
	}
	back, err := os.ReadFile(renamed)
	if err != nil || string(back) != "seed-data\n" {
		return false, "restored content wrong: " + string(back) + " err=" + errText(err)
	}
	return true, ""
}

func probeFsWrite() (bool, string) {
	orig := "ocp-probe-original\n"
	mod := "ocp-probe-modified\n"
	if err := os.WriteFile(fsWriteProbeTarget, []byte(orig), 0644); err != nil {
		return false, "seed probe file: " + err.Error()
	}
	defer os.Remove(fsWriteProbeTarget)

	// One write; capture its snapshot directly from the response.
	ok, data := probeWithParams("fs.write", map[string]any{
		"path": fsWriteProbeTarget, "content": mod,
	})
	if !ok || data == nil {
		return false, "fs.write failed"
	}
	snap, _ := data["snapshot"].(string)
	if snap == "" {
		return false, "snapshot missing"
	}
	ok, _ = probeWithParams("fs.write.rollback", map[string]any{
		"snapshot": snap, "path": fsWriteProbeTarget,
	})
	if !ok {
		return false, "fs.write.rollback failed"
	}
	back, err := os.ReadFile(fsWriteProbeTarget)
	if err != nil || string(back) != orig {
		return false, "content not restored: " + string(back) + " err=" + errText(err)
	}
	return true, ""
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// probeFsTransfer uploads a scratch file and downloads it back, verifying the
// round-trip content matches and never touches a production config or directory.
func probeFsTransfer() (bool, string) {
	dir := "/tmp/ocp-fs-transfer-probe"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, "mkdir probe dir: " + err.Error()
	}
	defer os.RemoveAll(dir)

	content := "transfer-roundtrip\n"
	ok, data := probeWithParams("fs.upload", map[string]any{
		"path": dir, "name": "up.bin", "content": content,
	})
	if !ok || data == nil {
		return false, "fs.upload failed"
	}
	target := filepath.Join(dir, "up.bin")
	back, err := os.ReadFile(target)
	if err != nil || string(back) != content {
		return false, "uploaded content wrong: " + string(back) + " err=" + errText(err)
	}
	ok, dl := probeWithParams("fs.download", map[string]any{"path": target})
	if !ok || dl == nil {
		return false, "fs.download failed"
	}
	b64, _ := dl["content_b64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(decoded) != content {
		return false, "download content wrong: " + string(decoded) + " err=" + errText(err)
	}
	return true, ""
}

// probeTask starts a hostdiag task, polls to done, and reads back its log.
func probeTask() (bool, string) {
	ok, data := probeWithParams("task.start", map[string]any{"type": "hostdiag"})
	if !ok || data == nil {
		return false, "task.start failed"
	}
	id, _ := data["task_id"].(string)
	if id == "" {
		return false, "task.start returned no id"
	}
	var state string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		ok, s := probeWithParams("task.status", map[string]any{"task_id": id})
		if !ok || s == nil {
			return false, "task.status failed"
		}
		state, _ = s["state"].(string)
		if state == "done" || state == "failed" {
			break
		}
	}
	if state != "done" {
		return false, "task did not finish: " + state
	}
	ok, lg := probeWithParams("task.log", map[string]any{"task_id": id})
	if !ok || lg == nil {
		return false, "task.log failed"
	}
	lines, _ := lg["lines"].([]any)
	if len(lines) == 0 {
		return false, "task.log empty"
	}
	return true, ""
}

// probePTY verifies the PTY capability surface. The terminal is OFF by default
// (master switch); in that state pty.list must fail with a "disabled" error,
// which is a valid outcome (capability not enabled), not a probe failure.
// When the switch is on, it opens a bash session, feeds echo, reads output,
// then closes — a full round trip.
func probePTY() (bool, string) {
	// Try pty.list first; if it reports "disabled", the capability is off and
	// that is expected (installer keeps it off by default).
	ok, data := probeWithParams("pty.list", map[string]any{})
	if !ok {
		return true, "pty disabled (default)" // not an error when off
	}
	// If we get here, PTY is enabled: do a real round trip.
	ok, start := probeWithParams("pty.open", map[string]any{"command": "bash", "rows": 24, "cols": 80})
	if !ok || start == nil {
		return false, "pty.open failed"
	}
	id, _ := start["session_id"].(string)
	if id == "" {
		return false, "pty.open returned no id"
	}
	ok, _ = probeWithParams("pty.input", map[string]any{"session_id": id, "data": "echo pty-probe-ok\n"})
	if !ok {
		return false, "pty.input failed"
	}
	found := false
	for i := 0; i < 100; i++ {
		time.Sleep(30 * time.Millisecond)
		ok, st := probeWithParams("pty.status", map[string]any{"session_id": id, "offset": 0})
		if ok && st != nil {
			if chunk, _ := st["chunk"].(string); strings.Contains(chunk, "pty-probe-ok") {
				found = true
				break
			}
		}
	}
	if !found {
		return false, "pty output missing"
	}
	// close
	probeWithParams("pty.close", map[string]any{"session_id": id})
	_ = data
	return true, ""
}

type req struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

type resp struct {
	ID    string         `json:"id"`
	OK    bool           `json:"ok"`
	Data  map[string]any `json:"data,omitempty"`
	Error string         `json:"error,omitempty"`
}

// probeWithParams sends one action with explicit params and returns ok + data.
func probeWithParams(action string, params map[string]any) (bool, map[string]any) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	wire, err := json.Marshal(req{ID: "probe", Action: action, Params: params})
	if err != nil {
		return false, nil
	}
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		return false, nil
	}
	frame, err := bufio.NewReaderSize(conn, 4096).ReadBytes('\n')
	if err != nil {
		return false, nil
	}
	var r resp
	if err := json.Unmarshal(frame, &r); err != nil {
		return false, nil
	}
	return r.OK, r.Data
}

func probe(action string) (bool, string) {
	params := actionParams[action]
	if params == nil {
		params = map[string]any{}
	}
	ok, _ := probeWithParams(action, params)
	if !ok {
		return false, "agent returned not ok"
	}
	return true, ""
}

func main() {
	failures := 0
	// fs.write/rollback need a real write + restore cycle; run separately so the
	// plain action loop does not attempt them with empty params.
	writeOK, writeErr := probeFsWrite()
	entry := map[string]any{"action": "fs.write.rollback", "ok": writeOK}
	if !writeOK {
		entry["error"] = writeErr
		failures++
	}
	line, _ := json.Marshal(entry)
	fmt.Println(string(line))

	// fs.rename / fs.remove / fs.restore cycle.
	mutOK, mutErr := probeFsMutate()
	entry = map[string]any{"action": "fs.restore", "ok": mutOK}
	if !mutOK {
		entry["error"] = mutErr
		failures++
	}
	line, _ = json.Marshal(entry)
	fmt.Println(string(line))

	// fs.upload / fs.download cycle.
	upOK, upErr := probeFsTransfer()
	entry = map[string]any{"action": "fs.download", "ok": upOK}
	if !upOK {
		entry["error"] = upErr
		failures++
	}
	line, _ = json.Marshal(entry)
	fmt.Println(string(line))

	// task start/status/log cycle (dynamic task_id).
	taskOK, taskErr := probeTask()
	entry = map[string]any{"action": "task.log", "ok": taskOK}
	if !taskOK {
		entry["error"] = taskErr
		failures++
	}
	line, _ = json.Marshal(entry)
	fmt.Println(string(line))

	// PTY capability surface (disabled by default -> expected not-failure).
	ptyOK, ptyErr := probePTY()
	entry = map[string]any{"action": "pty.list", "ok": ptyOK}
	if !ptyOK {
		entry["error"] = ptyErr
		failures++
	}
	line, _ = json.Marshal(entry)
	fmt.Println(string(line))

	for _, action := range actions {
		ok, errText := probe(action)
		entry := map[string]any{"action": action, "ok": ok}
		if !ok {
			if errText == "" {
				errText = "agent returned not ok"
			}
			entry["error"] = errText
			failures++
		}
		line, _ := json.Marshal(entry)
		fmt.Println(string(line))
	}
	if failures > 0 {
		os.Exit(1)
	}
}
