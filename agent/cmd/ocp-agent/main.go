package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Hermit-yu/OrangeCatPanel/agent/internal/actions"
	"github.com/Hermit-yu/OrangeCatPanel/agent/internal/audit"
)

func main() {
	sock := flag.String("sock", "/run/ocp/agent.sock", "unix socket path")
	auditPath := flag.String("audit", "/var/log/ocp/agent-audit.jsonl", "audit log path")
	flag.Parse()

	reg := actions.NewRegistry()
	a := audit.New(*auditPath)
	srv := reg.Serve()
	if err := srv.Start(*sock, a); err != nil {
		log.Fatalf("agent socket: %v", err)
	}
	// P5：终端能力默认关闭，只有 OCP_AGENT_PTY_ENABLED=1 才开启（独立开关）。
	if os.Getenv("OCP_AGENT_PTY_ENABLED") == "1" {
		actions.EnablePTY()
	}
	fmt.Printf("ocp-agent listening on %s, %d actions registered (pty=%v)\n", *sock, reg.Count(), actions.PTYEnabled())
	select {}
}
