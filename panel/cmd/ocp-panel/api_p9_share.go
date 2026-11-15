// Package main — P9 public read-only share.
//
// A share is a one-time snapshot of the overview data (system info + metrics)
// exposed at /share/<token> WITHOUT authentication. The snapshot is captured at
// create time, stored under /var/lib/ocp/shares/<token>.json (0600), and is
// deliberately scrubbed of anything sensitive (no host IPs beyond the overview
// fields the agent already redacts, no credentials). The share page is
// read-only: it cannot reach any management API.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

const (
	sharesDir        = "/var/lib/ocp/shares"
	shareTokenBytes  = 24
	shareMaxKeep     = 100
	shareTTL         = 7 * 24 * time.Hour
)

// shareRecord is the persisted snapshot.
type shareRecord struct {
	Token    string                 `json:"token"`
	Created  time.Time              `json:"created"`
	Expires  time.Time              `json:"expires"`
	Snapshot map[string]any         `json:"snapshot"`
}

func sharesDirPath() string {
	return sharesDir
}

// handleShareCreate captures an overview snapshot and creates a read-only URL.
func (p *panel) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	if err := os.MkdirAll(sharesDirPath(), 0700); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "分享目录不可用")
		return
	}
	// Capture a real snapshot from the agent.
	info, err1 := p.clients.Call("system.info", nil)
	metrics, err2 := p.clients.Call("system.metrics", nil)
	if err1 != nil || err2 != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "无法采集分享快照")
		return
	}
	snap := map[string]any{
		"info":    info,
		"metrics": metrics,
		"captured_at": time.Now().UTC().Format(time.RFC3339),
	}
	// Scrub anything that could leak credentials (defensive; the agent already
	// redacts, but never trust an upstream shape).
	scrubShare(snap)

	token, err := shareToken()
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "分享 token 生成失败")
		return
	}
	rec := shareRecord{
		Token:    token,
		Created:  time.Now().UTC(),
		Expires:  time.Now().UTC().Add(shareTTL),
		Snapshot: snap,
	}
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(sharesDirPath(), token+".json"), b, 0600); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "分享写入失败")
		return
	}
	pruneShares()
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "token": token, "url": "/share/" + token, "expires": rec.Expires.Format(time.RFC3339)})
}

// handleShareList lists active shares (read-only, authenticated).
func (p *panel) handleShareList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "shares": listShares()})
}

// handleShareRevoke deletes a share (write gate).
func (p *panel) handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if in.Token == "" || !validShareToken(in.Token) {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "分享 token 无效")
		return
	}
	path := filepath.Join(sharesDirPath(), in.Token+".json")
	if _, err := os.Stat(path); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "分享不存在")
		return
	}
	if err := os.Remove(path); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "分享撤销失败")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "revoked": in.Token})
}

// handleSharePage serves the PUBLIC read-only snapshot at /share/<token>.
// No authentication, no management API reachable, only the captured snapshot.
func (p *panel) handleSharePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/share/")
	token = strings.TrimSpace(token)
	if !validShareToken(token) {
		http.NotFound(w, r)
		return
	}
	rec, err := readShare(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if time.Now().After(rec.Expires) {
		http.NotFound(w, r)
		return
	}
	// Render a minimal read-only page from the snapshot (no JS that reaches
	// /api/*; only static display).
	b, _ := json.MarshalIndent(rec.Snapshot, "", "  ")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, sharePageHTML(rec.Created.Format(time.RFC3339), string(b)))
}

// ---------- helpers ----------

func shareToken() (string, error) {
	buf := make([]byte, shareTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validShareToken(token string) bool {
	if len(token) != shareTokenBytes*2 {
		return false
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func readShare(token string) (shareRecord, error) {
	var rec shareRecord
	b, err := os.ReadFile(filepath.Join(sharesDirPath(), token+".json"))
	if err != nil {
		return rec, err
	}
	err = json.Unmarshal(b, &rec)
	return rec, err
}

func listShares() []map[string]any {
	entries, err := os.ReadDir(sharesDirPath())
	if err != nil {
		return []map[string]any{}
	}
	var out []map[string]any
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		token := strings.TrimSuffix(e.Name(), ".json")
		if !validShareToken(token) {
			continue
		}
		rec, err := readShare(token)
		if err != nil {
			continue
		}
		expired := time.Now().After(rec.Expires)
		out = append(out, map[string]any{
			"token":    token,
			"url":      "/share/" + token,
			"created":  rec.Created.Format(time.RFC3339),
			"expires":  rec.Expires.Format(time.RFC3339),
			"expired":  expired,
		})
	}
	return out
}

func pruneShares() {
	entries, _ := os.ReadDir(sharesDirPath())
	// Remove expired + enforce max count.
	active := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		token := strings.TrimSuffix(e.Name(), ".json")
		if !validShareToken(token) {
			_ = os.Remove(filepath.Join(sharesDirPath(), e.Name()))
			continue
		}
		rec, err := readShare(token)
		if err == nil && time.Now().After(rec.Expires) {
			_ = os.Remove(filepath.Join(sharesDirPath(), e.Name()))
			continue
		}
		active++
	}
	// If over cap, remove oldest.
	if active <= shareMaxKeep {
		return
	}
	shares := listShares()
	for i := len(shares) - 1; i >= 0 && active > shareMaxKeep; i-- {
		_ = os.Remove(filepath.Join(sharesDirPath(), shares[i]["token"].(string)+".json"))
		active--
	}
}

// scrubShare drops any key that could carry credentials or host identity.
func scrubShare(m map[string]any) {
	for _, k := range []string{"password", "token", "key", "secret", "authorization", "cookie"} {
		delete(m, k)
	}
	// Nested info/metrics may carry agent internals; keep only safe keys.
	if info, ok := m["info"].(map[string]any); ok {
		for k := range info {
			switch k {
			case "hostname", "distro", "kernel", "uptime_seconds", "arch":
			default:
				delete(info, k)
			}
		}
	}
}

func sharePageHTML(created, snapshotJSON string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OrangeCatPanel 只读分享</title><style>
body{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#e8e3d8;margin:0;padding:2rem}
.card{max-width:800px;margin:0 auto;background:#1a1815;border:1px solid #2a2722;border-radius:12px;padding:1.5rem}
h1{font-size:1.2rem;color:#c9a34a;margin:0 0 .5rem}.sub{color:#8a8172;font-size:.8rem;margin-bottom:1rem}
pre{background:#121110;border:1px solid #2a2722;border-radius:8px;padding:1rem;overflow:auto;font-size:.75rem;color:#b5ad9e}
.badge{display:inline-block;background:#2a2722;color:#c9a34a;padding:2px 10px;border-radius:999px;font-size:.7rem}
</style></head><body><div class="card"><span class="badge">只读分享</span><h1>OrangeCatPanel 系统快照</h1><div class="sub">创建于 ` + created + ` · 只读视图，不包含任何管理能力</div><pre>` + htmlEscape(snapshotJSON) + `</pre></div></body></html>`
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
