//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func call(sock, action string) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Println("dial fail:", err)
		return
	}
	defer conn.Close()
	req := map[string]any{"id": "test", "action": action}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	enc.Encode(req)
	var resp map[string]any
	dec.Decode(&resp)
	b, _ := json.Marshal(resp)
	fmt.Printf("=== %s ===\n%s\n", action, string(b))
}

func main() {
	sock := "/run/ocp/agent.sock"
	_ = time.Now()
	for _, a := range []string{"system.info", "system.metrics", "docker.summary", "docker.containers", "nginx.sites", "net.interfaces", "processes"} {
		call(sock, a)
	}
}
