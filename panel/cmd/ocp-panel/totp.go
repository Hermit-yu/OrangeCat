package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// P9 认证增强：TOTP 两步验证。
//
// 状态持久化到 /var/lib/ocp/totp.json（0600）：{enabled, secret}。未启用时
// 登录仅需密码（现状）；启用后登录需密码 + TOTP code。启用流程：setup 生成
// secret + otpauth URL → enable 验证首个 code 后置 enabled=true。
//
// 凭据纪律：secret 只存 0600 文件，绝不落日志/响应体（setup 返回 otpauth
// URL 供用户扫码，不含明文 secret 之外的敏感值）。

const totpPath = "/var/lib/ocp/totp.json"

type totpState struct {
	Enabled bool   `json:"enabled"`
	Secret  string `json:"secret"`
}

// loadTOTP reads the persisted TOTP state; missing file = disabled.
func loadTOTP() totpState {
	var st totpState
	b, err := os.ReadFile(totpPath)
	if err != nil {
		return totpState{}
	}
	_ = json.Unmarshal(b, &st)
	return st
}

func saveTOTP(st totpState) error {
	b, _ := json.Marshal(st)
	if err := os.MkdirAll(dirOf(totpPath), 0700); err != nil {
		return err
	}
	tmp := totpPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, totpPath)
}

// totpEnabled reports whether TOTP is currently enforced.
func totpEnabled() bool {
	return loadTOTP().Enabled
}

// totpValidate checks a code against an arbitrary secret (setup-phase verify,
// before the secret is persisted as enabled). Returns (valid, error).
func totpValidate(secret, code string) (bool, error) {
	return totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
}

// verifyTOTP checks a 6-digit code against the stored secret. When TOTP is
// disabled, verification trivially succeeds (no second factor).
func verifyTOTP(code string) bool {
	st := loadTOTP()
	if !st.Enabled || st.Secret == "" {
		return true
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	valid, err := totpValidate(st.Secret, code)
	return err == nil && valid
}

// generateTOTPSecret creates a new TOTP secret for setup (not yet enabled).
func generateTOTPSecret(issuer, account string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		SecretSize:  16,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
