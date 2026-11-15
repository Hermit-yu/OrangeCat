package actions

import (
	"context"
	"path/filepath"
	"testing"
)

// TestClusterSingleNodeHonest: in single-node deployment the node list must
// report the local node as real/current and zero peers, never an invented
// cluster.
func TestClusterSingleNodeHonest(t *testing.T) {
	// Use a temp nodes file so the test does not touch the real registry.
	tmp := t.TempDir()
	orig := nodesFile
	nodesFile = filepath.Join(tmp, "agent-nodes.json")
	defer func() { nodesFile = orig }()

	res, err := ClusterNodes(context.Background(), nil)
	if err != nil {
		t.Fatalf("cluster.nodes should not error: %v", err)
	}
	if res["single_node"] != true || res["multi_node"] != false || res["cluster_ready"] != false {
		t.Fatalf("unexpected cluster state: %+v", res)
	}
	local, ok := res["local"].(*nodeRecord)
	if !ok {
		t.Fatalf("local node missing: %+v", res)
	}
	if local.Hostname == "" {
		t.Fatalf("local hostname empty")
	}
	peers, _ := res["peers"].([]any)
	if len(peers) != 0 {
		t.Fatalf("peers should be empty in single-node, got %d", len(peers))
	}
}

// TestClusterPairHonest: pairing without a second node returns not_configured.
func TestClusterPairHonest(t *testing.T) {
	res, err := ClusterPair(context.Background(), nil)
	if err != nil {
		t.Fatalf("pair should return structured result: %v", err)
	}
	if res["ok"] != false || res["not_configured"] != true {
		t.Fatalf("pair should be not_configured, got %+v", res)
	}
}

// TestClusterNodeDetailLocal: local node detail works and returns live facts.
func TestClusterNodeDetailLocal(t *testing.T) {
	res, err := ClusterNodeDetail(context.Background(), map[string]any{"id": "local"})
	if err != nil {
		t.Fatalf("local detail should work: %v", err)
	}
	if _, ok := res["node"]; !ok {
		t.Fatalf("node missing")
	}
	live, _ := res["live"].(map[string]any)
	if live["hostname"] == "" {
		t.Fatalf("live hostname empty")
	}
}
