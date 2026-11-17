// Package main extends the panel with P2 APIs: Docker images, networks,
// volumes, bounded logs, resource readings, and container lifecycle.
//
// 只读接口沿用 requireAuth（仅验 session），沿用既有 handler 的写法；
// 写接口走 requireWriteAccess 三重门（原站 + session + CSRF 双提交）并在每个
// 出口写审计，与 P1 的进程结束保持同一纪律。
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// ---------- P2 只读接口 ----------

func (p *panel) handleDockerImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("docker.images", nil)
	writeJSON(w, map[string]any{"images": data, "agent_error": errStr(err)})
}

func (p *panel) handleDockerNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("docker.networks", nil)
	writeJSON(w, map[string]any{"networks": data, "agent_error": errStr(err)})
}

func (p *panel) handleDockerVolumes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("docker.volumes", nil)
	writeJSON(w, map[string]any{"volumes": data, "agent_error": errStr(err)})
}

// maxLogLines bounds how far back the panel will ever ask the agent to go.
const maxLogLines = 500

// dockerNameRe mirrors the agent-side grammar: the panel must not be able to
// forward a name the agent would accept only because it is a single exec arg,
// and it must not be able to forward a traversal or a flag-like value.
var dockerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// parseDockerTarget validates the container name and optional bounded line
// count used by the log and stats endpoints.
func parseDockerTarget(r *http.Request) (name string, lines int, ok bool) {
	name = strings.TrimSpace(r.URL.Query().Get("name"))
	if !dockerNameRe.MatchString(name) {
		return "", 0, false
	}
	lines = maxLogLines
	raw := strings.TrimSpace(r.URL.Query().Get("lines"))
	if raw != "" {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || n < 1 || n > maxLogLines {
			return "", 0, false
		}
		lines = int(n)
	}
	return name, lines, true
}

func (p *panel) handleDockerLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	name, lines, ok := parseDockerTarget(r)
	if !ok {
		http.Error(w, "参数无效", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("docker.logs", map[string]any{"name": name, "lines": float64(lines)})
	writeJSON(w, map[string]any{"logs": data, "agent_error": errStr(err)})
}

func (p *panel) handleDockerStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	name, _, ok := parseDockerTarget(r)
	if !ok {
		http.Error(w, "参数无效", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("docker.stats", map[string]any{"name": name})
	writeJSON(w, map[string]any{"stats": data, "agent_error": errStr(err)})
}

func (p *panel) handleComposeProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("compose.projects", nil)
	writeJSON(w, map[string]any{"projects": data, "agent_error": errStr(err)})
}

func (p *panel) handleComposeValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	// 路径格式由 Agent 侧 isKnownComposePath 白名单做权威校验；这里只拒绝对空串。
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "参数无效", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("compose.validate", map[string]any{"path": path})
	writeJSON(w, map[string]any{"validate": data, "agent_error": errStr(err)})
}

func (p *panel) handleComposeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("compose.status", nil)
	writeJSON(w, map[string]any{"compose": data, "agent_error": errStr(err)})
}

// ---------- P2 写接口：Compose 项目生命周期 ----------

// composeActions is the closed compose write surface: only up and down are
// exposed. down never passes -v, so volumes are always preserved.
var composeActions = map[string]struct{}{
	"up": {}, "down": {},
}

// handleComposeAction starts or stops a known compose project behind the
// three-way write gate (Origin + session + CSRF), and audits every accepted
// call. The path is still re-checked against the discovery allowlist inside
// the agent action, so this cannot become a "run docker compose anywhere"
// primitive.
func (p *panel) handleComposeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeComposeAction); !ok {
		return
	}

	var in struct {
		Path   string `json:"path"`
		Action string `json:"action"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordComposeRejected(w, r, authaudit.ReasonComposeRequestBad, "请求格式无效", http.StatusBadRequest)
		return
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if _, allowed := composeActions[action]; !allowed {
		p.recordComposeRejected(w, r, authaudit.ReasonComposeRequestBad, "操作类型不受支持", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		p.recordComposeRejected(w, r, authaudit.ReasonComposeRequestBad, "路径为空", http.StatusBadRequest)
		return
	}

	data, err := p.clients.Call("compose."+action, map[string]any{"path": path})
	if err != nil {
		p.recordComposeRejected(w, r, authaudit.ReasonComposeActionFailed, errStr(err), http.StatusConflict)
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		reason, _ := data["error"].(string)
		if reason == "" {
			reason = "操作未执行"
		}
		p.recordComposeRejected(w, r, authaudit.ReasonComposeActionFailed, reason, http.StatusConflict)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeComposeAction, authaudit.OutcomeSuccess, authaudit.ReasonComposeActionSent); err != nil {
		log.Printf("Compose 操作审计写入失败: %v", err)
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

func (p *panel) recordComposeRejected(w http.ResponseWriter, r *http.Request, reason, message string, status int) {
	if err := p.recordAuth(r, authaudit.TypeComposeAction, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("Compose 操作审计写入失败: %v", err)
	}
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": message})
}

// ---------- P2 写接口：容器生命周期 ----------

// containerActions is the closed write surface. Anything else — including
// remove/execute/run — is refused at the panel layer, not merely ignored.
var containerActions = map[string]struct{}{
	"START": {}, "STOP": {}, "RESTART": {}, "KILL": {},
}

// handleContainerAction performs a container lifecycle operation behind the
// three-way write gate. KILL additionally demands an explicit force flag so an
// accidental click cannot hard-kill a production container.
func (p *panel) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeContainerAction); !ok {
		return
	}

	var in struct {
		Name   string `json:"name"`
		Action string `json:"action"`
		Force  bool   `json:"force"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordRejected(w, r, authaudit.ReasonContainerRequestBad, "请求格式无效", http.StatusBadRequest)
		return
	}
	action := strings.ToUpper(strings.TrimSpace(in.Action))
	if _, allowed := containerActions[action]; !allowed {
		p.recordRejected(w, r, authaudit.ReasonContainerRequestBad, "操作类型不受支持", http.StatusBadRequest)
		return
	}
	if !dockerNameRe.MatchString(strings.TrimSpace(in.Name)) {
		p.recordRejected(w, r, authaudit.ReasonContainerRequestBad, "容器名无效", http.StatusBadRequest)
		return
	}
	// 强制结束是这套操作里破坏性最强的一档，与进程的 SIGKILL 一样要求显式
	// force=true，让"不可逆操作"在面板上只有一个心智模型。
	if action == "KILL" && !in.Force {
		p.recordRejected(w, r, authaudit.ReasonContainerRequestBad, "强制结束容器必须显式 force=true", http.StatusBadRequest)
		return
	}

	data, err := p.clients.Call("docker.container.action", map[string]any{
		"name": strings.TrimSpace(in.Name), "action": action,
	})
	if err != nil {
		p.recordRejected(w, r, authaudit.ReasonContainerActionFailed, errStr(err), http.StatusConflict)
		return
	}
	// Agent 调用成功也可能 sent=false（容器不存在 / 状态不允许），只有真正执行
	// 才算成功，其余一律按失败码返回，避免前端把"未执行"显示成"已执行"。
	if sent, _ := data["sent"].(bool); !sent {
		reason, _ := data["reason"].(string)
		if reason == "" {
			reason = "操作未执行"
		}
		p.recordRejected(w, r, authaudit.ReasonContainerActionFailed, reason, http.StatusConflict)
		return
	}
	if err := p.recordAuth(r, authaudit.TypeContainerAction, authaudit.OutcomeSuccess, authaudit.ReasonContainerActionSent); err != nil {
		log.Printf("容器操作审计写入失败: %v", err)
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// recordRejected writes one rejection audit entry then the client-facing error.
// Shared by the P2 container endpoint; the P1 process-kill path keeps its own
// inline calls so both surfaces emit the same reason vocabulary.
func (p *panel) recordRejected(w http.ResponseWriter, r *http.Request, reason, message string, status int) {
	if err := p.recordAuth(r, authaudit.TypeContainerAction, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("容器操作审计写入失败: %v", err)
	}
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": message})
}
