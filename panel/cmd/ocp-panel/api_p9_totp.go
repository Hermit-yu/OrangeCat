// Package main — P9 TOTP setup/enable/disable APIs. All are write paths
// (three-way gate + audit). The secret never leaves the server; setup returns
// an otpauth URL for scanning and enable verifies the first code.
package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

// handleTOTPSetup generates a new TOTP secret (not yet enabled) and returns
// the otpauth URL. It does not change the enabled state.
func (p *panel) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	secret, url, err := generateTOTPSecret("OrangeCatPanel", "admin")
	if err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "TOTP 密钥生成失败")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "otpauth_url": url, "secret": secret, "enabled": false})
}

// handleTOTPEnable verifies the first code against the just-generated secret
// and flips enabled=true.
func (p *panel) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.Secret = strings.TrimSpace(in.Secret)
	if len(in.Secret) != 26 || len(in.Code) != 6 {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "secret/code 无效")
		return
	}
	valid, err := totpValidate(in.Secret, in.Code)
	if err != nil || !valid {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "验证码无效")
		return
	}
	if err := saveTOTP(totpState{Enabled: true, Secret: in.Secret}); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "TOTP 保存失败")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "enabled": true})
}

// handleTOTPDisable disables TOTP after verifying the current code.
func (p *panel) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	st := loadTOTP()
	if !st.Enabled {
		writeJSON(w, map[string]any{"ok": true, "enabled": false})
		return
	}
	if !verifyTOTP(in.Code) {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "验证码无效")
		return
	}
	if err := saveTOTP(totpState{}); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "TOTP 保存失败")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "enabled": false})
}

// handleTOTPStatus reports the current TOTP state (read-only).
func (p *panel) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	st := loadTOTP()
	writeJSON(w, map[string]any{"ok": true, "enabled": st.Enabled})
}
