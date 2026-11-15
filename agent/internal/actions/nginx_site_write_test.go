package actions

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestValidateSiteFields covers the closed parameter set and the field
// validators. It must never accept an extra field, a path traversal, a
// symlink target, or a non-http proxy.
func TestValidateSiteFields(t *testing.T) {
	good := map[string]any{
		"file":        nginxConfRoot + "/demo.taoque.top.conf",
		"server_name": "demo.taoque.top",
		"proxy_pass":  "http://172.18.0.1:8390",
		"mode":        "create",
	}
	content, err := validateSiteFields(good)
	if err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if !strings.Contains(content, "server_name demo.taoque.top;") {
		t.Fatalf("rendered content missing server_name: %q", content)
	}
	if !strings.Contains(content, "proxy_pass http://172.18.0.1:8390;") {
		t.Fatalf("rendered content missing proxy_pass: %q", content)
	}
	if strings.Contains(content, "root ") || strings.Contains(content, "location /app") {
		t.Fatalf("rendered content leaked non-proxy directives: %q", content)
	}

	bad := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"extra field", func(m map[string]any) { m["root"] = "/var/www" }},
		{"path traversal", func(m map[string]any) { m["file"] = nginxConfRoot + "/../../etc/cron.d/evil.conf" }},
		{"server_name with semicolon", func(m map[string]any) { m["server_name"] = "demo.com; root /evil;" }},
		{"server_name with slash", func(m map[string]any) { m["server_name"] = "demo.com/../evil" }},
		{"proxy_pass not http", func(m map[string]any) { m["proxy_pass"] = "file:///etc/passwd" }},
		{"proxy_pass with userinfo", func(m map[string]any) { m["proxy_pass"] = "http://user:pass@host" }},
		{"proxy_pass with semicolon", func(m map[string]any) { m["proxy_pass"] = "http://host;root /evil" }},
		{"mode invalid", func(m map[string]any) { m["mode"] = "delete" }},
		{"missing file", func(m map[string]any) { delete(m, "file") }},
		{"missing server_name", func(m map[string]any) { delete(m, "server_name") }},
		{"missing proxy_pass", func(m map[string]any) { delete(m, "proxy_pass") }},
	}
	// symlink case needs a real symlink on disk (Lstat must see it).
	symlinkPath := nginxConfRoot + "/.ocp-test-link.conf"
	_ = os.Symlink("/etc/passwd", symlinkPath)
	defer os.Remove(symlinkPath)
	bad = append(bad, struct {
		name   string
		mutate func(map[string]any)
	}{"symlink", func(m map[string]any) { m["file"] = symlinkPath }})
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range good {
				m[k] = v
			}
			tc.mutate(m)
			if _, err := validateSiteFields(m); err == nil {
				t.Fatalf("payload accepted: %v", m)
			}
		})
	}
}

// TestSiteServerNameRe checks the hostname/wildcard validator boundaries.
func TestSiteServerNameRe(t *testing.T) {
	ok := []string{"demo.taoque.top", "*.taoque.top", "a", "x1.y2.z3"}
	for _, s := range ok {
		if !siteServerNameRe.MatchString(s) {
			t.Fatalf("should accept %q", s)
		}
	}
	no := []string{"", "demo.com; root /evil", "demo.com/../evil", "a b", "*.", "a..b", "http://x"}
	for _, s := range no {
		if siteServerNameRe.MatchString(s) {
			t.Fatalf("should reject %q", s)
		}
	}
}

// TestSiteProxyPassRe checks the proxy URL validator boundaries.
func TestSiteProxyPassRe(t *testing.T) {
	ok := []string{"http://172.18.0.1:8390", "https://example.com", "http://host:8080/app", "http://1.2.3.4"}
	for _, s := range ok {
		if !siteProxyPassRe.MatchString(s) {
			t.Fatalf("should accept %q", s)
		}
	}
	no := []string{"", "file:///etc/passwd", "http://user:pass@host", "http://host;root /evil", "http://host#frag", "javascript:alert(1)"}
	for _, s := range no {
		if siteProxyPassRe.MatchString(s) {
			t.Fatalf("should reject %q", s)
		}
	}
}

// TestNginxSiteValidateModeChecks checks the create/update existence gating
// without touching disk (validation only).
func TestNginxSiteValidateModeChecks(t *testing.T) {
	// mode create on an existing file -> ok:false (not an error)
	existing := map[string]any{
		"file":        nginxConfRoot + "/www.taoque.top.conf",
		"server_name": "www.taoque.top",
		"proxy_pass":  "http://127.0.0.1:8080",
		"mode":        "create",
	}
	res, err := NginxSiteValidate(context.Background(), existing)
	if err != nil {
		t.Fatalf("expected structured result, got error: %v", err)
	}
	if ok, _ := res["ok"].(bool); ok {
		t.Fatalf("create on existing should be ok:false")
	}
}
