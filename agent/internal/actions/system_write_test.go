package actions

import (
	"context"
	"testing"
)

// TestSystemWriteValidation covers hostname/timezone field validators and the
// closed parameter sets. These never touch the system (validation only).
func TestSystemWriteValidation(t *testing.T) {
	// hostname valid
	valid := []string{"ocp-host", "taoque", "a1", "x-y-3"}
	for _, v := range valid {
		if got, err := validateHostname(v); err != nil || got != v {
			t.Fatalf("validateHostname(%q) = %q, %v", v, got, err)
		}
	}
	// hostname invalid
	invalid := []string{"", "a b", "demo.com; rm -rf /", "-leading", "trailing-", ".", "a..b", "http://x"}
	for _, v := range invalid {
		if _, err := validateHostname(v); err == nil {
			t.Fatalf("validateHostname(%q) should reject", v)
		}
	}
	// timezone regex boundaries
	if !timezoneRe.MatchString("Asia/Shanghai") {
		t.Fatalf("timezone should accept Asia/Shanghai")
	}
	if !timezoneRe.MatchString("UTC") {
		t.Fatalf("timezone should accept single-segment UTC")
	}
	if !timezoneRe.MatchString("Etc/GMT+8") {
		t.Fatalf("timezone should accept Etc/GMT+8")
	}
	for _, v := range []string{"", "Asia/Shanghai; rm -rf /", "../etc/passwd", "UTC/../etc", "a b", "-leading"} {
		if timezoneRe.MatchString(v) {
			t.Fatalf("timezone should reject %q", v)
		}
	}
}

// TestSystemWriteClosedParamSet ensures extra fields are rejected (no
// injection into hostnamectl/timedatectl arguments).
func TestSystemWriteClosedParamSet(t *testing.T) {
	// dry_run preview must be pure read (no system mutation).
	res, err := SystemHostnameSet(context.Background(), map[string]any{"hostname": "ocp-host", "dry_run": true})
	if err != nil {
		t.Fatalf("dry_run hostname should not error: %v", err)
	}
	if res["dry_run"] != true || res["new"] != "ocp-host" {
		t.Fatalf("unexpected preview: %+v", res)
	}
	if _, err := SystemHostnameSet(context.Background(), map[string]any{"hostname": "ocp-host", "extra": "x"}); err == nil {
		t.Fatalf("extra field should be rejected")
	}
	if _, err := SystemTimezoneSet(context.Background(), map[string]any{"timezone": "Asia/Shanghai", "dry_run": true}); err != nil {
		t.Fatalf("dry_run timezone should not error: %v", err)
	}
	if _, err := SystemTimezoneSet(context.Background(), map[string]any{"timezone": "Asia/Shanghai", "extra": "x"}); err == nil {
		t.Fatalf("extra field should be rejected")
	}
}

// TestSystemSSHStatusReadOnly ensures the read-only status returns a real
// port or empty and never claims port changes are supported.
func TestSystemSSHStatusReadOnly(t *testing.T) {
	res, err := SystemSSHStatus(context.Background(), nil)
	if err != nil {
		t.Fatalf("read-only status should not error: %v", err)
	}
	if res["port_changes_supported"] != false {
		t.Fatalf("port changes must not be claimed supported")
	}
	// Port may be "22" (real) or "" (unreadable); either is honest.
	if p, _ := res["port"].(string); p != "22" && p != "" {
		t.Fatalf("unexpected port value: %v", p)
	}
}
