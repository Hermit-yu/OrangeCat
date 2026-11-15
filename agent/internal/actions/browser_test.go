package actions

import "testing"

// TestValidateBrowserURL: only public http(s) URLs pass; loopback/private/
// cloud-metadata/non-http are rejected.
func TestValidateBrowserURL(t *testing.T) {
	ok := []string{
		"https://example.com",
		"http://example.com/path?q=1",
		"https://github.com/Hermit-yu/OrangeCatPanel",
	}
	for _, u := range ok {
		if err := validateBrowserURL(u); err != nil {
			t.Fatalf("should allow %q: %v", u, err)
		}
	}
	bad := []string{
		"http://127.0.0.1:8390/",
		"http://localhost/",
		"http://192.168.1.1/",
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"file:///etc/passwd",
		"ftp://example.com",
		"",
		"notaurl",
		"javascript:alert(1)",
	}
	for _, u := range bad {
		if err := validateBrowserURL(u); err == nil {
			t.Fatalf("should reject %q", u)
		}
	}
}

// TestBrowserStatusDisabled: default (env not set) is disabled + honest not_ready.
func TestBrowserStatusDisabled(t *testing.T) {
	res, err := BrowserStatus(nil, nil)
	if err != nil {
		t.Fatalf("status error: %v", err)
	}
	if res["enabled"] != false {
		t.Fatalf("enabled = %v, want false (default off)", res["enabled"])
	}
	if res["not_ready"] != true {
		t.Fatalf("not_ready = %v, want true (disabled)", res["not_ready"])
	}
}
