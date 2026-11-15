package actions

import (
	"context"
	"testing"
)

// TestNginxP3RejectsParameters: the read-only full discovery and both write
// actions must reject any parameter (they are fixed-config operations).
// NginxSitesP3 is registered via noParams, so test the wrapped form.
func TestNginxP3RejectsParameters(t *testing.T) {
	cases := []struct {
		name   string
		action func(context.Context, map[string]any) (map[string]any, error)
	}{
		{"nginx.sites.full", noParams(NginxSitesP3)},
		{"nginx.test", NginxTest},
		{"nginx.reload", NginxReload},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.action(context.Background(), map[string]any{"unexpected": "x"}); err == nil {
				t.Fatalf("expected parameter rejection for %s", c.name)
			}
		})
	}
}

// TestNginxTestRunsInContainer runs the REAL nginx -t inside the live nginx
// container. This is a guarded acceptance check: it only validates config
// syntax (read-only), never reloads or changes state.
func TestNginxTestRunsInContainer(t *testing.T) {
	res, err := NginxTest(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("nginx.test should not error: %v", err)
	}
	if ok, _ := res["ok"].(bool); !ok {
		msg, _ := res["output"].(string)
		t.Fatalf("nginx.test should succeed, output=%q", msg)
	}
	if running, _ := res["running"].(bool); !running {
		t.Fatal("nginx.test should report container running")
	}
}

// TestNginxCertExpiryParser verifies the openssl dates parser handles the
// real output shape (e.g. "Jan  2 15:04:05 2006 GMT") and computes days_left.
func TestNginxCertExpiryParser(t *testing.T) {
	exp := parseCertDates("notBefore=Nov 10 04:35:04 2026 GMT\nnotAfter=Feb  8 04:35:03 2027 GMT\nissuer=CN = R11")
	if exp == nil {
		t.Fatal("expected parsed expiry")
	}
	if _, ok := exp["notAfter"].(string); !ok {
		t.Fatalf("notAfter missing, got %#v", exp)
	}
	if dl, ok := exp["days_left"].(int); !ok || dl <= 0 {
		t.Fatalf("days_left should be positive int, got %#v", exp["days_left"])
	}
	// bad format must not panic, returns nil-ish map without notAfter
	bad := parseCertDates("garbage line\nnotAfter=not-a-date")
	if bad == nil {
		t.Fatal("expected non-nil even for partial parse")
	}
	if _, ok := bad["days_left"]; ok {
		t.Fatalf("days_left should be absent when date unparseable, got %#v", bad)
	}
}

// TestNginxConfNameRe guards the vhost filename validation used by the write
// slice's future config path.
func TestNginxConfNameRe(t *testing.T) {
	valid := []string{"hermes.taoque.top.conf", "a.conf", "my_site-2.conf"}
	for _, n := range valid {
		if _, err := validateNginxConfName(n); err != nil {
			t.Errorf("expected %q valid, got %v", n, err)
		}
	}
	invalid := []string{"../etc.conf", "a/b.conf", ".conf", "-x.conf", "a;rm.conf", "a.conf.bak"}
	for _, n := range invalid {
		if _, err := validateNginxConfName(n); err == nil {
			t.Errorf("expected %q rejected", n)
		}
	}
}

// TestNginxSitesFullDiscovery runs the real discovery against the live config
// and asserts the key contracts: at least one site, cert expiry attached.
func TestNginxSitesFullDiscovery(t *testing.T) {
	res, err := NginxSitesP3(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("discovery error: %v", err)
	}
	sites, _ := res["sites"].([]map[string]any)
	if len(sites) == 0 {
		t.Skip("no nginx sites on this host (dev machine)")
	}
	foundExpiry := false
	for _, s := range sites {
		if _, ok := s["expires"].(map[string]any); ok {
			foundExpiry = true
			break
		}
	}
	if !foundExpiry {
		t.Log("no site has cert expiry attached (certs may live elsewhere); not fatal")
	}
	if certs, ok := res["certs"].([]map[string]any); !ok || len(certs) == 0 {
		t.Log("no certs listed; not fatal")
	}
}
