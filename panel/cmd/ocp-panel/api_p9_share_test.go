package main

import (
	"strings"
	"testing"
)

// TestShareTokenValid: generated tokens are 48 hex chars and validate.
func TestShareTokenValid(t *testing.T) {
	tok, err := shareToken()
	if err != nil {
		t.Fatalf("token gen error: %v", err)
	}
	if len(tok) != shareTokenBytes*2 {
		t.Fatalf("token length = %d, want %d", len(tok), shareTokenBytes*2)
	}
	if !validShareToken(tok) {
		t.Fatalf("generated token should validate")
	}
	for _, bad := range []string{"", "short", strings.Repeat("g", 48), "zz" + strings.Repeat("a", 46)} {
		if validShareToken(bad) {
			t.Fatalf("should reject %q", bad)
		}
	}
}

// TestScrubShareRemovesSensitive: scrubbing drops credential keys and keeps
// only safe overview fields.
func TestScrubShareRemovesSensitive(t *testing.T) {
	m := map[string]any{
		"info": map[string]any{
			"hostname": "taoque", "distro": "Ubuntu", "kernel": "6.8",
			"password": "x", "token": "y", "key": "z",
		},
		"metrics": map[string]any{"cpu": 1},
		"secret":  "leak",
	}
	scrubShare(m)
	if _, ok := m["secret"]; ok {
		t.Fatalf("secret should be scrubbed")
	}
	info, _ := m["info"].(map[string]any)
	if _, ok := info["password"]; ok {
		t.Fatalf("password should be scrubbed from info")
	}
	if _, ok := info["hostname"]; !ok {
		t.Fatalf("hostname should be kept")
	}
	if _, ok := info["token"]; ok {
		t.Fatalf("token should be scrubbed")
	}
}
