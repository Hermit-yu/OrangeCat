package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// P4 写切片：单文件原子写（fs.write / fs.write.rollback）。
//
// 写接口统一走 requireWriteAccess 三重门（原站 + session + CSRF 双提交），
// 每个出口（成功 / 请求无效 / agent 失败 / 审计失败）都写审计，与 P1/P2/P3
// 保持同一纪律。请求体上限 1 MiB（与 agent 侧 fsWriteMaxBytes 一致），
// 类型化参数（path/content/snapshot 均为字符串），不做任意 shell 转发。
//
// 安全边界（与只读切片一致）：路径规范化而非根 confinement；只写已存在的
// 常规文件（新建/上传留给后续切片）；rollback 目标路径必须显式传入且快照
// 必须位于 agent 管理的快照目录（agent 侧二次校验）。

const fsWriteRequestMaxBytes = 1 << 20

// handleFsWrite atomically replaces one existing file with a pre-write snapshot.
func (p *panel) handleFsWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsWrite); !ok {
		return
	}

	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, fsWriteRequestMaxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordFsRejected(w, r, authaudit.ReasonFsWriteRequestBad, "请求格式无效")
		return
	}
	path := strings.TrimSpace(in.Path)
	if path == "" || in.Content == "" {
		p.recordFsRejected(w, r, authaudit.ReasonFsWriteRequestBad, "路径与内容必填")
		return
	}

	data, err := p.clients.Call("fs.write", map[string]any{
		"path": path, "content": in.Content,
	})
	if err != nil {
		p.recordFsRejected(w, r, authaudit.ReasonFsWriteFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsRejected(w, r, authaudit.ReasonFsWriteFailed, "写入未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsWrite, authaudit.OutcomeSuccess, authaudit.ReasonFsWriteSent); err != nil {
		log.Printf("文件写审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleFsWriteRollback restores a file from a prior snapshot.
func (p *panel) handleFsWriteRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsWrite); !ok {
		return
	}

	var in struct {
		Snapshot string `json:"snapshot"`
		Path     string `json:"path"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordFsRejected(w, r, authaudit.ReasonFsRollbackRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.Snapshot) == "" || strings.TrimSpace(in.Path) == "" {
		p.recordFsRejected(w, r, authaudit.ReasonFsRollbackRequestBad, "快照与路径必填")
		return
	}

	data, err := p.clients.Call("fs.write.rollback", map[string]any{
		"snapshot": strings.TrimSpace(in.Snapshot), "path": strings.TrimSpace(in.Path),
	})
	if err != nil {
		p.recordFsRejected(w, r, authaudit.ReasonFsRollbackFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsRejected(w, r, authaudit.ReasonFsRollbackFailed, "回滚未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsWrite, authaudit.OutcomeSuccess, authaudit.ReasonFsRollbackSent); err != nil {
		log.Printf("文件回滚审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// recordFsRejected writes one rejection audit entry then the client-facing
// error, using the fs_write type and the passed reason.
func (p *panel) recordFsRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeFsWrite, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("文件写审计写入失败: %v", err)
	}
	writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": message})
}
