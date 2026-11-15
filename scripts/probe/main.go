// Package main probes the ocp-agent unix socket with one request per action.
// Prints one JSON line per action; exits non-zero unless all succeed.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
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

// probeFsWrite exercises fs.write and fs.write.rollback against a private
// scratch file, then verifies the original content came back.
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
