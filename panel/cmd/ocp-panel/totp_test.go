package main

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestGenerateAndValidateTOTP: a generated secret produces a code that
// validates (setup phase), and a wrong code is rejected.
func TestGenerateAndValidateTOTP(t *testing.T) {
	secret, url, err := generateTOTPSecret("OrangeCatPanel", "admin")
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	if len(secret) != 26 {
		t.Fatalf("secret length = %d, want 26 (16 bytes base32)", len(secret))
	}
	if !strings.Contains(url, "otpauth://") {
		t.Fatalf("url should be otpauth scheme: %q", url)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code error: %v", err)
	}
	valid, err := totpValidate(secret, code)
	if err != nil || !valid {
		t.Fatalf("valid code should validate (err=%v)", err)
	}
	valid, _ = totpValidate(secret, "000000")
	if valid {
		t.Fatalf("wrong code should be rejected")
	}
}

// TestVerifyTOTPDisabledSucceeds: when TOTP is not enabled, any code passes
// (no second factor).
func TestVerifyTOTPDisabledSucceeds(t *testing.T) {
	if !verifyTOTP("") {
		t.Fatalf("disabled TOTP should always pass")
	}
	if !verifyTOTP("123456") {
		t.Fatalf("disabled TOTP should pass any code")
	}
}
