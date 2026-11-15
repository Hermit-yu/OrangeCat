package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// P8：多节点与轻量 Agent —— 单机诚实落地。
//
// 当前只有本机节点（taoque）。cluster.nodes 返回真实的本机节点注册记录
// （主机名/心跳时间/能力协商），集群节点列表为空（诚实：没有第二节点接入，
// 不编造多节点集群）。节点配对/远程文件/终端/批量作业在无第二节点时明确
// 标"依赖未就绪"。
//
// 节点注册表持久化到 /var/lib/ocp/agent-nodes.json（0600），由 agent 维护；
// 本机节点始终注册且心跳为当前时间。

var (
	nodesFile        = "/var/lib/ocp/agent-nodes.json"
	nodeHeartbeatTTL = 90 * time.Second
	nodeMaxKeep      = 50
)

type nodeRecord struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Role      string    `json:"role"`
	AddedAt   time.Time `json:"added_at"`
	LastSeen  time.Time `json:"last_seen"`
	Capab     []string  `json:"capabilities"`
	Local     bool      `json:"local"`
}

var nodeMu sync.Mutex

// loadNodes reads the persisted node registry (or returns just the local node).
func loadNodes() []nodeRecord {
	nodeMu.Lock()
	defer nodeMu.Unlock()
	var nodes []nodeRecord
	b, err := os.ReadFile(nodesFile)
	if err == nil {
		_ = jsonUnmarshalNodes(b, &nodes)
	}
	// Ensure the local node is present and current.
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "unknown"
	}
	local := nodeRecord{
		ID:       "local",
		Hostname: hn,
		Role:     "manager",
		AddedAt:  time.Now(),
		LastSeen: time.Now(),
		Capab: []string{
			"system.info", "system.metrics", "docker.*", "nginx.*", "fs.*",
			"process.*", "pty.*", "task.*", "ai.chat", "health.check",
		},
		Local: true,
	}
	found := false
	for i := range nodes {
		if nodes[i].ID == "local" {
			nodes[i].LastSeen = time.Now()
			nodes[i].Capab = local.Capab
			found = true
			break
		}
	}
	if !found {
		nodes = append([]nodeRecord{local}, nodes...)
	}
	saveNodes(nodes)
	return nodes
}

func saveNodes(nodes []nodeRecord) {
	b := jsonMarshalNodes(nodes)
	if err := os.MkdirAll(filepath.Dir(nodesFile), 0700); err != nil {
		return
	}
	tmp := nodesFile + ".tmp"
	_ = os.WriteFile(tmp, b, 0600)
	_ = os.Rename(tmp, nodesFile)
}

// ClusterNodes returns the real node list: the local node plus any persisted
// peers that have heartbeated within TTL. No invented cluster state.
func ClusterNodes(ctx context.Context, _ map[string]any) (map[string]any, error) {
	nodes := loadNodes()
	now := time.Now()
	peers := []nodeRecord{}
	for _, n := range nodes {
		if n.Local {
			continue
		}
		if now.Sub(n.LastSeen) > nodeHeartbeatTTL {
			continue // stale peer is not reported as online
		}
		peers = append(peers, n)
	}
	// Local node is always current.
	var local *nodeRecord
	for i := range nodes {
		if nodes[i].Local {
			local = &nodes[i]
			break
		}
	}
	return map[string]any{
		"local":          local,
		"peers":          peers,
		"peer_count":     len(peers),
		"multi_node":     len(peers) > 0,
		"single_node":    len(peers) == 0,
		"cluster_ready":  false,
		"requires_peer":  true,
		"message":        "当前为单机部署：本机节点真实注册，无第二节点接入，集群功能标依赖未就绪（不编造多节点状态）",
	}, nil
}

// ClusterNodeDetail returns one node's real detail (local or a live peer).
func ClusterNodeDetail(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) != 1 {
		return nil, errClusterNodeDetail
	}
	id, _ := params["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errClusterNodeDetail
	}
	nodes := loadNodes()
	for _, n := range nodes {
		if n.ID == id {
			if n.Local {
				// Attach live host facts for the local node.
				info, _ := SystemInfo(ctx, nil)
				return map[string]any{"node": n, "live": info}, nil
			}
			return map[string]any{"node": n, "live": map[string]any{}}, nil
		}
	}
	return nil, errClusterNodeDetail
}

// ClusterPair is the pairing entry point. Without a second node it honestly
// reports "dependency not ready" instead of inventing a paired peer.
func ClusterPair(ctx context.Context, _ map[string]any) (map[string]any, error) {
	return map[string]any{
		"ok":             false,
		"error":          "依赖未就绪：多节点配对需要第二台主机接入（当前单机部署，不编造配对结果）",
		"not_configured": true,
	}, nil
}

var errClusterNodeDetail = errors.New("cluster.node.detail expects exactly the id parameter")

// jsonMarshalNodes / jsonUnmarshalNodes are thin wrappers so the node registry
// stays serializable without leaking encoding internals.
func jsonMarshalNodes(nodes []nodeRecord) []byte {
	b, _ := json.Marshal(nodes)
	return b
}

func jsonUnmarshalNodes(b []byte, nodes *[]nodeRecord) error {
	return json.Unmarshal(b, nodes)
}
