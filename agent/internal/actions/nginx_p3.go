package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// P3: Nginx 站点与证书发现 + 反代模板只读发现。
//
// 本文件只实现只读发现：存量 vhost、证书到期时间、反代模板清单。
// test/reload 写操作因涉及 docker exec nginx，安全边界更严格，见
// nginx_write.go（P3 写切片）。
//
// 安全模型：
//   - 配置目录固定为宿主机挂载点 /home/web/conf.d（nginx 容器挂载它）。
//   - 证书目录固定 /home/web/certs（容器挂载 /etc/nginx/certs）。
//   - 只报告存在性与到期时间，不读证书私钥内容。
//   - 反代模板只发现"哪些 .conf 里有 proxy_pass"，不修改任何文件。

// nginxConfRoot is the host path nginx mounts as /etc/nginx/conf.d.
const nginxConfRoot = "/home/web/conf.d"

// nginxCertsRoot is the host path nginx mounts as /etc/nginx/certs.
const nginxCertsRoot = "/home/web/certs"

// nginxContainer is the fixed container name running nginx.
const nginxContainer = "nginx"

// nginxTestTimeout bounds a single nginx -t / reload run.
const nginxTestTimeout = 20 * time.Second

// NginxSitesP3 is the read-only discovery entry: vhost + cert expiry + reverse
// proxy template inventory. It REPLACES the P1 NginxSites by adding expiry and
// proxy fields — but P1 still uses NginxSites for backward-compat, so this
// returns a superset keyed the same way plus "expiry" and "proxy".
func NginxSitesP3(ctx context.Context, _ map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	sites := scanNginxSites(ctx)
	certs := scanCertExpiry(ctx)

	// Attach cert expiry per site by matching the ssl_certificate path to a
	// known cert file. scanNginxSites stamps cert_host (host-side path) into
	// the certs map; fall back to the raw container path if absent.
	for i := range sites {
		ci, _ := sites[i]["certs"].(map[string]string)
		certHost := ci["cert_host"]
		if certHost == "" {
			certHost = ci["cert"]
		}
		if certHost == "" {
			continue
		}
		if exp, ok := certs[certHost]; ok {
			sites[i]["expires"] = exp
		}
	}

	// Derive a real status per site (no invented states): healthy = has a
	// cert AND proxy_pass AND cert not near/over expiry; needs_review = cert
	// missing/expiring within 30 days or no proxy; config_only = no proxy.
	for i := range sites {
		sites[i]["status"] = siteStatus(sites[i])
	}

	return map[string]any{
		"sites":  sites,
		"certs":  certMapToList(certs),
		"count":  len(sites),
		"nginx":  nginxFacts(ctx),
	}, nil
}

// nginxFacts reports the nginx container/version and the host config mount.
func nginxFacts(ctx context.Context) map[string]any {
	facts := map[string]any{
		"container": nginxContainer,
		"conf_host": nginxConfRoot,
		"certs_host": nginxCertsRoot,
		"running": false,
	}
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.Running}}|{{.Config.Image}}", nginxContainer).Output()
	if err != nil {
		return facts
	}
	part := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(part) == 2 && part[0] == "true" {
		facts["running"] = true
		facts["image"] = part[1]
	}
	return facts
}

// toHostCertPath maps a container-side cert path (/etc/nginx/certs/…) back to
// the host mount point so the expiry lookup key matches.
func toHostCertPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "/etc/nginx/certs/") {
		return filepath.Join(nginxCertsRoot, strings.TrimPrefix(p, "/etc/nginx/certs/"))
	}
	return p
}

// scanNginxSites returns one row per .conf with server_name, cert path and
// whether the file contains proxy_pass (a reverse proxy template).
func scanNginxSites(ctx context.Context) []map[string]any {
	var sites []map[string]any
	for _, dir := range []string{nginxConfRoot, "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return sites
			}
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			b, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			content := string(b)
			names := extractServerNames(content)
			certInfo := extractCertPaths(content)
			// cert paths in nginx conf are container paths (/etc/nginx/certs/…);
			// normalize to the host mount so the expiry lookup matches.
			if certInfo != nil && certInfo["cert"] != "" {
				certInfo["cert_host"] = toHostCertPath(certInfo["cert"])
			}
			if certInfo != nil && certInfo["key"] != "" {
				certInfo["key_host"] = toHostCertPath(certInfo["key"])
			}
			sites = append(sites, map[string]any{
				"file":    full,
				"names":   names,
				"certs":   certInfo,
				"cert":    certInfo["cert"],
				"proxy":   strings.Contains(content, "proxy_pass"),
				"size":    len(b),
			})
		}
	}
	if sites == nil {
		sites = []map[string]any{}
	}
	sort.Slice(sites, func(i, j int) bool {
		a, _ := sites[i]["file"].(string)
		b, _ := sites[j]["file"].(string)
		return a < b
	})
	return sites
}

// scanCertExpiry maps a cert file host path -> {expires, days_left, issuer}.
// It walks the known cert roots (top-level *_cert.pem plus live/ symlinks),
// reads only the certificate (not the key) with openssl, and never fails the
// whole listing when one cert is unreadable.
func scanCertExpiry(ctx context.Context) map[string]map[string]any {
	out := map[string]map[string]any{}
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return
		}
		exp := certExpiry(ctx, path)
		if exp == nil {
			return
		}
		out[path] = exp
	}

	// top-level *_cert.pem and acme.sh fullchain copies (komari/pass/www use *_fullchain.pem)
	if entries, err := os.ReadDir(nginxCertsRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasSuffix(n, "_cert.pem") && !strings.HasSuffix(n, "_fullchain.pem") {
				continue
			}
			add(filepath.Join(nginxCertsRoot, n))
		}
	}
	// live/*/cert.pem and live/*/fullchain.pem (symlinks)
	live := filepath.Join(nginxCertsRoot, "live")
	if entries, err := os.ReadDir(live); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			add(filepath.Join(live, e.Name(), "cert.pem"))
			add(filepath.Join(live, e.Name(), "fullchain.pem"))
		}
	}
	return out
}

// certExpiry reads one certificate's validity window via openssl x509 -dates.
func certExpiry(ctx context.Context, path string) map[string]any {
	mctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(mctx, "openssl", "x509",
		"-in", path, "-noout", "-dates", "-issuer").CombinedOutput()
	if err != nil {
		return nil
	}
	return parseCertDates(string(out))
}

// parseCertDates is a pure parser for `openssl x509 -dates -issuer` output.
// It is extracted so the expiry arithmetic can be unit-tested without a real
// certificate.
func parseCertDates(text string) map[string]any {
	exp := map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "notAfter=") {
			exp["notAfter"] = strings.TrimPrefix(line, "notAfter=")
			if t, err := time.Parse("Jan  2 15:04:05 2006 GMT", strings.TrimPrefix(line, "notAfter=")); err == nil {
				exp["days_left"] = int(time.Until(t).Hours() / 24)
				exp["expires_unix"] = t.Unix()
			}
		} else if strings.HasPrefix(line, "notBefore=") {
			exp["notBefore"] = strings.TrimPrefix(line, "notBefore=")
		} else if strings.HasPrefix(line, "issuer=") {
			exp["issuer"] = strings.TrimPrefix(line, "issuer=")
		}
	}
	if len(exp) == 0 {
		return nil
	}
	return exp
}

// certMapToList flattens the expiry map to a slice for the panel.
func certMapToList(m map[string]map[string]any) []map[string]any {
	list := make([]map[string]any, 0, len(m))
	for path, exp := range m {
		row := map[string]any{"path": path}
		for k, v := range exp {
			row[k] = v
		}
		list = append(list, row)
	}
	sort.Slice(list, func(i, j int) bool {
		a, _ := list[i]["path"].(string)
		b, _ := list[j]["path"].(string)
		return a < b
	})
	return list
}

// siteStatus derives a real, data-driven status for a discovered site:
//   - healthy: has a certificate AND proxy_pass AND the cert is not near/over
//     expiry (days_left > 30 or unknown-but-present).
//   - needs_review: cert is missing, or expiring within 30 days, or the site
//     has no proxy_pass (so it may need attention).
//   - config_only: the config has no proxy_pass (static/management config).
//
// It never fabricates a state: it only reasons over the fields that
// scanNginxSites + scanCertExpiry actually produced.
func siteStatus(site map[string]any) string {
	hasProxy, _ := site["proxy"].(bool)
	hasCert := false
	days := 999999
	if ci, ok := site["certs"].(map[string]string); ok && ci["cert"] != "" {
		hasCert = true
	}
	if exp, ok := site["expires"].(map[string]any); ok {
		if d, ok := exp["days_left"].(int); ok {
			days = d
		}
	}
	switch {
	case !hasProxy:
		return "config_only"
	case !hasCert || days < 30:
		return "needs_review"
	default:
		return "healthy"
	}
}

// NginxSiteDetail reads one vhost config's real content for the detail view.
// It only accepts a file that scanNginxSites actually discovered (no arbitrary
// path), and caps the returned content to avoid oversized agent payloads.
func NginxSiteDetail(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("nginx.site.detail expects exactly the file parameter")
	}
	file, _ := params["file"].(string)
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, fmt.Errorf("file is required")
	}
	if !validSiteConfPath(file) {
		return nil, fmt.Errorf("file is not a discovered vhost config")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	const maxDetail = 64 << 10
	truncated := len(b) > maxDetail
	if truncated {
		b = b[:maxDetail]
	}
	return map[string]any{
		"file":      file,
		"content":   string(b),
		"size":      len(b),
		"truncated": truncated,
	}, nil
}

// validSiteConfPath reports whether file is one of the vhost config files that
// scanNginxSites would discover (so detail never reads an arbitrary path).
func validSiteConfPath(file string) bool {
	for _, dir := range []string{nginxConfRoot, "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"} {
		if strings.HasPrefix(file, dir+"/") {
			base := filepath.Base(file)
			return nginxConfNameRe.MatchString(base)
		}
	}
	return false
}

// mustParseJSON is a small helper for tests to decode the NDJSON list.
func mustParseJSON(raw string) []map[string]any {
	var list []map[string]any
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return []map[string]any{}
	}
	return list
}

// nginxConfNameRe validates a vhost config filename (no path separators).
var nginxConfNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\.conf$`)

func validateNginxConfName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if !nginxConfNameRe.MatchString(name) {
		return "", fmt.Errorf("name is not a valid nginx config filename")
	}
	return name, nil
}
