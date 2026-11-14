package agentbridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCallRejectsOversizedRequestBeforeDial(t *testing.T) {
	client := New(filepath.Join(t.TempDir(), "no-socket"))
	_, err := client.Call("system.info", map[string]any{"value": strings.Repeat("x", 70<<10)})
	if err == nil || !strings.Contains(err.Error(), "request exceeds size limit") {
		t.Fatalf("Call error = %v, want local request-size rejection", err)
	}
}

func TestCallRejectsOversizedResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := bufio.NewReader(conn).ReadBytes('\n'); err != nil {
			serverErr <- err
			return
		}
		_, err = fmt.Fprintf(conn, `{"id":"panel","ok":true,"data":{"value":"%s"}}`+"\n", strings.Repeat("x", (1<<20)+1))
		serverErr <- err
	}()

	_, err = New(path).Call("system.info", nil)
	if err == nil || !strings.Contains(err.Error(), "response exceeds size limit") {
		t.Fatalf("Call error = %v, want response-size rejection", err)
	}
	if err := <-serverErr; err != nil && !os.IsTimeout(err) {
		t.Fatalf("fake server write failed unexpectedly: %v", err)
	}
}

func TestCallRejectsMismatchedResponseID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request req
		_ = json.NewDecoder(conn).Decode(&request)
		_ = json.NewEncoder(conn).Encode(resp{ID: "unexpected", OK: true, Data: map[string]any{"hostname": "test"}})
	}()
	if _, err := New(path).Call("system.info", nil); err == nil || !strings.Contains(err.Error(), "response id mismatch") {
		t.Fatalf("Call error = %v, want response ID mismatch", err)
	}
}
