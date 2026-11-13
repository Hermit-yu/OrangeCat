package main

import (
	"flag"
	"fmt"
	"log"

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
	fmt.Printf("ocp-agent listening on %s, %d actions registered\n", *sock, reg.Count())
	select {}
}
