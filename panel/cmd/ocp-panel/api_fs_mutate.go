package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// P4-3 写切片：改名 / 删除 / 恢复。
//
// 统一走 requireWriteAccess 三重门 + 逐出口审计（与 P4-2 同纪律）。删除必须
// force=true 显式确认（破坏性动作只有一个心智模型）。恢复需显式传目标路径
// 与快照（或 dir=true 重建空目录）。

// handleFsRename renames a file or empty directory.
func (p *panel) handleFsRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsMutate); !ok {
		return
	}
	var in struct {
		Path    string `json:"path"`
		NewPath string `json:"new_path"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRenameRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.Path) == "" || strings.TrimSpace(in.NewPath) == "" {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRenameRequestBad, "源与目标路径必填")
		return
	}
	data, err := p.clients.Call("fs.rename", map[string]any{
		"path": strings.TrimSpace(in.Path), "new_path": strings.TrimSpace(in.NewPath),
	})
	if err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRenameFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRenameFailed, "改名未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsMutate, authaudit.OutcomeSuccess, authaudit.ReasonFsRenameSent); err != nil {
		log.Printf("文件改名审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleFsRemove deletes a file or empty directory (force required).
func (p *panel) handleFsRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsMutate); !ok {
		return
	}
	var in struct {
		Path  string `json:"path"`
		Force bool   `json:"force"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRemoveRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.Path) == "" {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRemoveRequestBad, "路径必填")
		return
	}
	if !in.Force {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRemoveRequestBad, "删除必须显式 force=true")
		return
	}
	data, err := p.clients.Call("fs.remove", map[string]any{
		"path": strings.TrimSpace(in.Path), "force": true,
	})
	if err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRemoveFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRemoveFailed, "删除未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsMutate, authaudit.OutcomeSuccess, authaudit.ReasonFsRemoveSent); err != nil {
		log.Printf("文件删除审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleFsRestore brings back a removed file or empty directory.
func (p *panel) handleFsRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsMutate); !ok {
		return
	}
	var in struct {
		Path     string `json:"path"`
		Snapshot string `json:"snapshot"`
		Dir      bool   `json:"dir"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRestoreRequestBad, "请求格式无效")
		return
	}
	if strings.TrimSpace(in.Path) == "" {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRestoreRequestBad, "路径必填")
		return
	}
	params := map[string]any{"path": strings.TrimSpace(in.Path)}
	if in.Dir {
		params["dir"] = true
	} else {
		if strings.TrimSpace(in.Snapshot) == "" {
			p.recordFsMutateRejected(w, r, authaudit.ReasonFsRestoreRequestBad, "快照必填")
			return
		}
		params["snapshot"] = strings.TrimSpace(in.Snapshot)
	}
	data, err := p.clients.Call("fs.restore", params)
	if err != nil {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRestoreFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsMutateRejected(w, r, authaudit.ReasonFsRestoreFailed, "恢复未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsMutate, authaudit.OutcomeSuccess, authaudit.ReasonFsRestoreSent); err != nil {
		log.Printf("文件恢复审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// recordFsMutateRejected writes one rejection audit entry then the client error.
func (p *panel) recordFsMutateRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeFsMutate, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("文件变更审计写入失败: %v", err)
	}
	writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": message})
}
