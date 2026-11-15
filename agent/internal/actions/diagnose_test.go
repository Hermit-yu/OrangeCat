package actions

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestIsAllowedProbeHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want bool
	}{
		{"public whitelisted", "1.1.1.1", true},
		{"public dns", "8.8.8.8", true},
		{"loopback", "127.0.0.1", false},
		{"private", "10.1.2.3", false},
		{"private 172", "172.16.0.1", false},
		{"private 192", "192.168.1.1", false},
		{"link-local", "169.254.1.1", false},
		{"dns name", "example.com", false},
		{"not whitelisted", "9.9.9.9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowedProbeHost(tc.host); got != tc.want {
				t.Fatalf("isAllowedProbeHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestParseAllowedProbeURLRejectsPrivate(t *testing.T) {
	for name, raw := range map[string]string{
		"private ip": "http://192.168.1.1/",
		"loopback":   "http://127.0.0.1:8390/",
		"bad scheme": "ftp://1.1.1.1/",
		"good":       "https://1.1.1.1/cdn-cgi/trace",
	} {
		t.Run(name, func(t *testing.T) {
			u, err := parseAllowedProbeURL(raw)
			if name == "good" {
				if err != nil || u == nil {
					t.Fatalf("expected success, got err=%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected rejection for %q", raw)
			}
		})
	}
}

func TestLinkDiagnosticsRejectsUnknownParams(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"unknown":                {"bogus": 1},
		"bad host":               {"host": "192.168.1.1"},
		"private url":            {"url": "http://10.0.0.5/"},
		"ok defaults":            {},
		"extra whitelisted host": {"host": "8.8.8.8"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LinkDiagnostics(context.Background(), params)
			if name == "ok defaults" || name == "extra whitelisted host" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected rejection for params=%v", params)
			}
		})
	}
}

func TestKillProcessRejectsInvalidParams(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"missing pid":   {},
		"string pid":    {"pid": "123"},
		"zero pid":      {"pid": float64(0)},
		"negative pid":  {"pid": float64(-1)},
		"unknown key":   {"pid": float64(1), "path": "/etc/passwd"},
		"bad signal":    {"pid": float64(1), "signal": "HUP"},
		"kill no force": {"pid": float64(1), "signal": "KILL"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := KillProcess(context.Background(), params); err == nil {
				t.Fatalf("KillProcess(%v) accepted invalid params", params)
			}
		})
	}
}

func TestKillProcessMissingPidReportsNotFound(t *testing.T) {
	// pick a pid that almost certainly does not exist on this host
	_, err := KillProcess(context.Background(), map[string]any{
		"pid":   float64(4194000),
		"force": true,
	})
	if err != nil {
		t.Fatalf("KillProcess(pid=4194000) returned hard error %v; want soft not-found", err)
	}
}

func TestServicesRejectsUnknownParams(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"empty":    {},
		"filter":   {"filter": "nginx"},
		"unknown":  {"filter": "nginx", "shell": "rm -rf /"},
		"too long": {"filter": strings.Repeat("x", 70)},
	} {
		if name == "unknown" || name == "too long" {
			if _, err := Services(context.Background(), params); err == nil {
				t.Fatalf("Services(%v) accepted invalid params", params)
			}
			continue
		}
		// real systemctl call on this host: just ensure it does not panic
		if runtime.GOOS == "linux" {
			_, _ = Services(context.Background(), params)
		}
	}
}

func TestHealthCheckRejectsBadScope(t *testing.T) {
	for _, params := range []map[string]any{
		{"scope": "nonsense"},
		{"unknown": 1},
	} {
		if _, err := HealthCheck(context.Background(), params); err == nil {
			t.Fatalf("HealthCheck(%v) accepted invalid params", params)
		}
	}
	// quick scope runs on a real host and must return a report map
	if runtime.GOOS == "linux" {
		report, err := HealthCheck(context.Background(), map[string]any{"scope": "quick"})
		if err != nil {
			t.Fatalf("HealthCheck(quick) error: %v", err)
		}
		if _, ok := report["overall"]; !ok {
			t.Fatalf("report missing overall: %+v", report)
		}
		checks, ok := report["checks"].(map[string]any)
		if !ok || len(checks) == 0 {
			t.Fatalf("report checks empty: %+v", report)
		}
	}
}
