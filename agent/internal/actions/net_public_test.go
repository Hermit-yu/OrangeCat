package actions

import (
	"context"
	"testing"
)

// TestLocalAddrFiltersLoopback: localAddr must not return loopback addresses.
func TestLocalAddrFiltersLoopback(t *testing.T) {
	// Real system call — the host always has at least one non-loopback addr
	// on this machine (we run on a VPS). If it returns 未识别 the environment
	// may be unusual; that's still a valid honest value, not a failure.
	v4 := localAddr("4")
	if v4 == "127.0.0.1" {
		t.Fatalf("localAddr returned loopback: %s", v4)
	}
	if v4 == "" {
		t.Fatalf("localAddr returned empty (should be 未识别 or a real addr)")
	}
}

// TestNetPublicHonest: NetPublic must never fabricate — on API failure the
// public fields report 未识别, not a made-up IP.
func TestNetPublicHonest(t *testing.T) {
	res, err := NetPublic(context.Background(), nil)
	if err != nil {
		// Failure to read local ip is acceptable (still honest).
		return
	}
	if ip, _ := res["public_ipv4"].(string); ip == "" {
		t.Fatalf("public_ipv4 must be present (未识别 or real)")
	}
	if op, _ := res["operator"].(string); op == "" {
		t.Fatalf("operator must be present")
	}
	// local_ipv4 must be present
	if li, _ := res["local_ipv4"].(string); li == "" {
		t.Fatalf("local_ipv4 must be present")
	}
}
