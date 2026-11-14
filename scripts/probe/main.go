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
	"docker.summary",
	"docker.containers",
	"nginx.sites",
	"net.interfaces",
	"processes",
}

type req struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

type resp struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func probe(action string) (bool, string) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	wire, err := json.Marshal(req{ID: "probe", Action: action, Params: map[string]any{}})
	if err != nil {
		return false, err.Error()
	}
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		return false, err.Error()
	}
	frame, err := bufio.NewReaderSize(conn, 4096).ReadBytes('\n')
	if err != nil {
		return false, err.Error()
	}
	var r resp
	if err := json.Unmarshal(frame, &r); err != nil {
		return false, err.Error()
	}
	if r.ID != "probe" {
		return false, "response id mismatch"
	}
	return r.OK, r.Error
}

func main() {
	failures := 0
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
