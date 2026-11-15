package actions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Services lists systemd service states. Fixed subcommand and args only (R3:
// no user input reaches the shell). Optional "filter" param selects a
// substring; results are capped at 200 entries.
func Services(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		if key != "filter" {
			return nil, fmt.Errorf("services accepts only the 'filter' parameter")
		}
	}
	filter, _ := p["filter"].(string)
	filter = strings.TrimSpace(filter)
	if len(filter) > 64 {
		return nil, errors.New("filter too long")
	}
	args := []string{"list-units", "--type=service", "--no-legend", "--no-pager", "--plain"}
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil {
		// systemctl list-units may return non-zero on partial failure;
		// treat empty/error as unavailable rather than fabricating data.
		if out == nil || len(out) == 0 {
			return map[string]any{"available": false, "error": err.Error(), "services": []map[string]any{}}, nil
		}
	}
	var services []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		if name == "" || strings.HasPrefix(name, "@") {
			continue
		}
		loaded, active, sub := fields[1], fields[2], fields[3]
		if filter != "" && !strings.Contains(name, filter) {
			continue
		}
		services = append(services, map[string]any{
			"name":   name,
			"loaded": loaded,
			"active": active,
			"sub":    sub,
		})
	}
	sort.Slice(services, func(i, j int) bool { return services[i]["name"].(string) < services[j]["name"].(string) })
	if len(services) > 200 {
		services = services[:200]
	}
	if services == nil {
		services = []map[string]any{}
	}
	// unit-level enablement state (best-effort; not fatal when unavailable)
	enabled := map[string]any{}
	if out, err := exec.CommandContext(ctx, "systemctl", "is-enabled", "--no-pager", "ocp-panel", "ocp-agent").CombinedOutput(); err == nil {
		for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			names := []string{"ocp-agent", "ocp-panel"}
			if i < len(names) {
				enabled[names[i]] = strings.TrimSpace(line)
			}
		}
	}
	return map[string]any{
		"available": true,
		"services":  services,
		"count":     len(services),
		"notable":   enabled,
	}, nil
}

// LinkDiagnostics runs bounded ping/TCP/HTTP probes against an explicit,
// validated whitelist of targets (R3: no arbitrary shell; no private-network
// targets). Each probe has a hard deadline.
func LinkDiagnostics(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		switch key {
		case "host", "url":
		default:
			return nil, fmt.Errorf("net.diagnostics accepts only host, url")
		}
	}
	type probeTarget struct {
		name string
		host string
		kind string // "ping" | "tcp" | "http"
		port string
		url  string
	}
	targets := []probeTarget{
		{"cloudflare-tcp", "1.1.1.1", "tcp", "443", ""},
		{"cloudflare-tls", "1.1.1.1", "http", "443", "https://1.1.1.1/cdn-cgi/trace"},
		{"baidu-ping", "223.5.5.5", "ping", "", ""},
		{"ali-dns-ping", "114.114.114.114", "ping", "", ""},
	}
	// allow the operator to add extra targets via params (validated)
	if extra, ok := p["host"].(string); ok && extra != "" {
		if !isAllowedProbeHost(extra) {
			return nil, fmt.Errorf("host not in probe whitelist: %q", extra)
		}
		targets = append(targets, probeTarget{name: "extra-" + extra, host: extra, kind: "tcp", port: "443", url: ""})
	}
	if extraURL, ok := p["url"].(string); ok && extraURL != "" {
		u, err := parseAllowedProbeURL(extraURL)
		if err != nil {
			return nil, err
		}
		targets = append(targets, probeTarget{name: "extra-url", host: u.Hostname(), kind: "http", port: u.Port(), url: extraURL})
	}

	// each probe gets its own bounded deadline so one slow target
	// cannot drain the whole request budget.
	results := []map[string]any{}
	for _, t := range targets {
		rec := map[string]any{"target": t.name, "host": t.host, "kind": t.kind}
		probe, cancelProbe := context.WithTimeout(ctx, 8*time.Second)
		switch t.kind {
		case "ping":
			rec = pingProbe(probe, t.host, rec)
		case "tcp":
			rec = tcpProbe(probe, t.host, t.port, rec)
		case "http":
			rec = httpProbe(probe, t.url, rec)
		}
		cancelProbe()
		results = append(results, rec)
	}
	return map[string]any{"available": true, "results": results}, nil
}

func pingProbe(ctx context.Context, host string, rec map[string]any) map[string]any {
	out, err := exec.CommandContext(ctx, "ping", "-c", "2", "-W", "2", host).CombinedOutput()
	if err != nil {
		rec["ok"] = false
		rec["error"] = "ping: " + err.Error()
		// still surface any rtt that made it to output
		if m := rttRegex.FindStringSubmatch(string(out)); m != nil {
			rec["rtt_ms"] = m[1]
		}
		return rec
	}
	loss := ""
	rtt := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "packet loss") {
			loss = line
		}
		if m := rttRegex.FindStringSubmatch(line); m != nil {
			rtt = m[1]
		}
	}
	rec["ok"] = true
	rec["loss"] = loss
	if rtt != "" {
		rec["rtt_ms"] = rtt
	}
	return rec
}

func tcpProbe(ctx context.Context, host, port string, rec map[string]any) map[string]any {
	if port == "" {
		port = "443"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 4*time.Second)
	if err != nil {
		rec["ok"] = false
		rec["error"] = "tcp: " + err.Error()
		return rec
	}
	defer conn.Close()
	rec["ok"] = true
	rec["port"] = port
	return rec
}

func httpProbe(ctx context.Context, url string, rec map[string]any) map[string]any {
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		rec["ok"] = false
		rec["error"] = "http: " + err.Error()
		return rec
	}
	resp, err := client.Do(req)
	if err != nil {
		rec["ok"] = false
		rec["error"] = "http: " + err.Error()
		return rec
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 512)
	rec["ok"] = true
	rec["status"] = resp.StatusCode
	return rec
}

var rttRegex = regexp.MustCompile(`time=(\d+(?:\.\d+)?) ms`)

// Allowed probe hosts: public well-known endpoints plus a small public set.
var allowedProbeHosts = map[string]struct{}{
	"1.1.1.1": {}, "8.8.8.8": {}, "8.8.4.4": {}, "223.5.5.5": {}, "114.114.114.114": {},
}

var allowedProbeURLs = []string{
	"https://1.1.1.1/cdn-cgi/trace", "http://1.1.1.1/",
}

func isAllowedProbeHost(host string) bool {
	// only bare public IPs from the whitelist are accepted; DNS names and
	// private/local ranges are rejected (SSRF guard).
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return false
		}
		if isPrivateOrLocal(a.As4()) {
			return false
		}
		_, ok := allowedProbeHosts[a.String()]
		return ok
	}
	_, ok := allowedProbeHosts[host]
	return ok
}

func isPrivateOrLocal(a [4]byte) bool {
	// 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0.0.0.0/8, 224/4, 240/4, 255.255.255.255
	switch {
	case a[0] == 10:
		return true
	case a[0] == 172 && a[1] >= 16 && a[1] <= 31:
		return true
	case a[0] == 192 && a[1] == 168:
		return true
	case a[0] == 127:
		return true
	case a[0] == 169 && a[1] == 254:
		return true
	case a[0] == 0:
		return true
	case a[0] >= 224 && a[0] < 240:
		return true
	case a[0] >= 240:
		return true
	}
	return false
}

func parseAllowedProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("url must be http or https")
	}
	host := u.Hostname()
	if !isAllowedProbeHost(host) {
		return nil, fmt.Errorf("url host not allowed: %q", host)
	}
	return u, nil
}
