package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// P4-4 切片：上传（multipart）与下载（octet-stream）。
//
// 上传：POST multipart/form-data，字段 `path`（目标目录，绝对路径）+ `file`
// （文件）。panel 读入文件内容（有界 1MiB），转发 agent fs.upload；agent 侧
// 负责目录存在性、文件名穿越校验、覆盖前快照与原子替换。
// 下载：GET ?path=，调 agent fs.download（base64 内容，含二进制），解码后以
// application/octet-stream + Content-Disposition 附件流回。
//
// 两者都走 requireWriteAccess 三重门 + 逐出口审计（下载虽只读，但暴露文件
// 内容，与 nginx.test 同理走写门防止匿名探测任意路径）。

const fsUploadMaxBytes = 1 << 20

// handleFsUpload accepts one multipart file and writes it into a directory.
func (p *panel) handleFsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsUpload); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, fsUploadMaxBytes+1<<16)
	if err := r.ParseMultipartForm(fsUploadMaxBytes + 1<<16); err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadRequestBad, "请求格式无效或过大")
		return
	}
	dir := strings.TrimSpace(r.FormValue("path"))
	if dir == "" {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadRequestBad, "目标目录必填")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadRequestBad, "缺少文件")
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, fsUploadMaxBytes+1))
	if err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, "读取文件失败")
		return
	}
	if len(content) > fsUploadMaxBytes {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, "文件超过 1MiB 上限")
		return
	}
	if strings.ContainsAny(filepath.Base(header.Filename), "/\\") || strings.TrimSpace(header.Filename) == "" {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadRequestBad, "文件名无效")
		return
	}
	data, err := p.clients.Call("fs.upload", map[string]any{
		"path": dir, "name": filepath.Base(header.Filename), "content": string(content),
	})
	if err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, errStr(err))
		return
	}
	if ok, _ := data["ok"].(bool); !ok {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, "上传未执行")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsUpload, authaudit.OutcomeSuccess, authaudit.ReasonFsUploadSent); err != nil {
		log.Printf("上传审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": data})
}

// handleFsDownload streams one file back as an attachment.
func (p *panel) handleFsDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeFsUpload); !ok {
		return
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "参数无效", http.StatusBadRequest)
		return
	}
	data, err := p.clients.Call("fs.download", map[string]any{"path": path})
	if err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, errStr(err))
		return
	}
	b64, _ := data["content_b64"].(string)
	if b64 == "" {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, "下载内容为空")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		p.recordFsUploadRejected(w, r, authaudit.ReasonFsUploadFailed, "内容解码失败")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeFsUpload, authaudit.OutcomeSuccess, authaudit.ReasonFsUploadSent); err != nil {
		log.Printf("下载审计写入失败: %v", err)
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+sanitizeDownloadName(filepath.Base(path)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// sanitizeDownloadName keeps the attachment filename to a safe ASCII-ish form.
func sanitizeDownloadName(name string) string {
	var b strings.Builder
	for _, rn := range name {
		if (rn >= 'a' && rn <= 'z') || (rn >= 'A' && rn <= 'Z') || (rn >= '0' && rn <= '9') || rn == '.' || rn == '-' || rn == '_' {
			b.WriteRune(rn)
		}
	}
	if b.Len() == 0 {
		return "download"
	}
	return b.String()
}

// recordFsUploadRejected writes one rejection audit entry then the client error.
func (p *panel) recordFsUploadRejected(w http.ResponseWriter, r *http.Request, reason, message string) {
	if err := p.recordAuth(r, authaudit.TypeFsUpload, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("上传审计写入失败: %v", err)
	}
	writeJSON(w, map[string]any{"ok": false, "result": nil, "agent_error": message})
}
