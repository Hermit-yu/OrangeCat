package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// P6 写切片：站点变更（反代 vhost 的新增/修改/删除）。
//
// 安全模型刻意收窄，防止配置注入：
//   - 只接受反代场景的两个字段：server_name + proxy_pass。
//   - server_name 必须匹配域名/通配符白名单，proxy_pass 必须匹配 http(s)://
//     host[:port][/path] 白名单，其余任何 nginx 指令一律拒绝。
//   - 写路径只允许 conf.d 下的 *.conf（复用 validSiteConfPath），拒绝路径
//     穿越/符号链接。
//   - 原子写 tmp+rename 0600；写前备份到 conf.d/.ocp-backups/。
//   - 写后容器内 nginx -t 校验，失败自动回滚备份，绝不留下半配置。
//   - 成功才 reload。
//
// 三个动作：nginx.site.validate（模板校验，不写盘）、nginx.site.save
// （新增/修改）、nginx.site.delete（删除）。全部要求显式参数，不接收
// 额外字段，防意外注入。

// siteWriteTimeout bounds a single nginx write round (backup+write+test+reload).
const siteWriteTimeout = 30 * time.Second

// nginxConfRootHost is the host-side conf.d root (also used by scanNginxSites).
// The nginx container mounts /home/web/conf.d as /etc/nginx/conf.d.
const nginxConfRootHost = nginxConfRoot

// siteServerNameRe validates a server_name token: a single hostname label,
// wildcard label, or a dotted name; up to 253 chars, no spaces/semicolons.
// Labels are separated by single dots; no empty labels (rejects a..b).
var siteServerNameRe = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,62})?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62})?)*$`)

// siteProxyPassRe validates a proxy_pass URL: http(s)://host[:port][/path],
// host is a hostname or IP literal; no userinfo, no fragment, no semicolon.
var siteProxyPassRe = regexp.MustCompile(`^https?://[a-zA-Z0-9.\-]+(:\d{1,5})?(/[a-zA-Z0-9/._\-%]*)?$`)

// validateSiteFields validates the save payload fields, returning the
// rendered vhost config content. It returns an error if any field is present
// beyond the closed set.
func validateSiteFields(params map[string]any) (string, error) {
	// Closed parameter set: file, server_name, proxy_pass, mode.
	allowed := map[string]bool{"file": true, "server_name": true, "proxy_pass": true, "mode": true}
	for k := range params {
		if !allowed[k] {
			return "", fmt.Errorf("unsupported field: %s", k)
		}
	}
	file, _ := params["file"].(string)
	file = strings.TrimSpace(file)
	if file == "" {
		return "", fmt.Errorf("file is required")
	}
	if !validSiteConfPath(file) {
		return "", fmt.Errorf("file is not a discovered vhost config")
	}
	name, _ := params["server_name"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("server_name is required")
	}
	if !siteServerNameRe.MatchString(name) {
		return "", fmt.Errorf("server_name is not a valid hostname/wildcard")
	}
	proxy, _ := params["proxy_pass"].(string)
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return "", fmt.Errorf("proxy_pass is required")
	}
	if !siteProxyPassRe.MatchString(proxy) {
		return "", fmt.Errorf("proxy_pass is not a valid http(s) URL")
	}
	mode, _ := params["mode"].(string)
	if mode == "" {
		mode = "create"
	}
	if mode != "create" && mode != "update" {
		return "", fmt.Errorf("mode must be create or update")
	}
	// Reject path traversal / symlink escape: the resolved path must stay
	// inside the conf.d root.
	root := filepath.Clean(nginxConfRootHost)
	target := filepath.Clean(file)
	if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return "", fmt.Errorf("file escapes conf.d root")
	}
	if fi, err := os.Lstat(file); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("file is a symlink; refusing to write")
	}
	// Render the reverse-proxy vhost. Only the two fields above are emitted;
	// no other nginx directive can be injected via this path.
	content := fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n\n    location / {\n        proxy_pass %s;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n", name, proxy)
	return content, nil
}

// NginxSiteValidate validates the save payload and, for an existing file,
// checks the current file matches expectations (no partial state). It does
// NOT write anything.
func NginxSiteValidate(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("nginx.site.validate requires parameters")
	}
	content, err := validateSiteFields(params)
	if err != nil {
		return nil, err
	}
	file, _ := params["file"].(string)
	exists := false
	if _, err := os.Stat(file); err == nil {
		exists = true
	}
	mode, _ := params["mode"].(string)
	if mode == "" {
		mode = "create"
	}
	// A create must not clobber an existing vhost; an update must target one.
	if mode == "create" && exists {
		return map[string]any{"ok": false, "error": "vhost already exists (use update mode)"}, nil
	}
	if mode == "update" && !exists {
		return map[string]any{"ok": false, "error": "vhost does not exist (use create mode)"}, nil
	}
	return map[string]any{
		"ok":      true,
		"file":    file,
		"mode":    mode,
		"content": content,
		"bytes":   len(content),
	}, nil
}

// siteBackupDir is where pre-write snapshots of vhost configs are kept.
const siteBackupDir = nginxConfRootHost + "/.ocp-backups"

// NginxSiteSave writes (create or update) a vhost config atomically, backs up
// any existing file, runs nginx -t in the container, and reloads on success.
// On test failure it restores the backup and returns a structured error.
func NginxSiteSave(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("nginx.site.save requires parameters")
	}
	content, err := validateSiteFields(params)
	if err != nil {
		return nil, err
	}
	file, _ := params["file"].(string)
	mode, _ := params["mode"].(string)
	if mode == "" {
		mode = "create"
	}

	ctx, cancel := context.WithTimeout(ctx, siteWriteTimeout)
	defer cancel()

	// Snapshot the existing file (if any) so we can roll back on test failure.
	var backupPath string
	hadExisting := false
	if _, err := os.Stat(file); err == nil {
		hadExisting = true
		backupPath, err = backupSiteConf(ctx, file)
		if err != nil {
			return nil, fmt.Errorf("backup existing config: %w", err)
		}
	}
	if mode == "create" && hadExisting {
		return map[string]any{"ok": false, "error": "vhost already exists (use update mode)"}, nil
	}
	if mode == "update" && !hadExisting {
		return map[string]any{"ok": false, "error": "vhost does not exist (use create mode)"}, nil
	}

	// Atomic write: tmp file in the same dir + rename.
	tmp := file + ".ocp-tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	_ = os.Chmod(tmp, 0644) // nginx reads world-readable; keep parity with existing confs
	if err := os.Rename(tmp, file); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("install config: %w", err)
	}

	// Validate inside the nginx container; on failure roll back the backup.
	ok, output := nginxTestInContainer(ctx)
	if !ok {
		rollbackSiteConf(ctx, file, backupPath, hadExisting)
		return map[string]any{
			"ok":       false,
			"rolled":   true,
			"output":   output,
			"rollback": rollbackInfo(file, backupPath, hadExisting),
		}, nil
	}
	// Reload so the new vhost takes effect. Reload failure is also rolled back.
	reloadOut := nginxReloadInContainer(ctx)
	if reloadOut != "" {
		rollbackSiteConf(ctx, file, backupPath, hadExisting)
		return map[string]any{
			"ok":       false,
			"rolled":   true,
			"output":   reloadOut,
			"rollback": rollbackInfo(file, backupPath, hadExisting),
		}, nil
	}

	return map[string]any{
		"ok":      true,
		"file":    file,
		"mode":    mode,
		"bytes":   len(content),
		"backup":  backupPath,
		"created": !hadExisting,
	}, nil
}

// NginxSiteDelete removes a vhost config after backing it up, then validates
// and reloads; on test failure it restores the backup.
func NginxSiteDelete(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("nginx.site.delete expects exactly the file parameter")
	}
	file, _ := params["file"].(string)
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, fmt.Errorf("file is required")
	}
	if !validSiteConfPath(file) {
		return nil, fmt.Errorf("file is not a discovered vhost config")
	}
	ctx, cancel := context.WithTimeout(ctx, siteWriteTimeout)
	defer cancel()
	if _, err := os.Stat(file); err != nil {
		return nil, fmt.Errorf("vhost does not exist")
	}
	backupPath, err := backupSiteConf(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("backup before delete: %w", err)
	}
	if err := os.Remove(file); err != nil {
		return nil, fmt.Errorf("remove config: %w", err)
	}
	ok, output := nginxTestInContainer(ctx)
	if !ok {
		rollbackSiteConf(ctx, file, backupPath, true)
		return map[string]any{
			"ok":       false,
			"rolled":   true,
			"output":   output,
			"rollback": rollbackInfo(file, backupPath, true),
		}, nil
	}
	reloadOut := nginxReloadInContainer(ctx)
	if reloadOut != "" {
		rollbackSiteConf(ctx, file, backupPath, true)
		return map[string]any{
			"ok":       false,
			"rolled":   true,
			"output":   reloadOut,
			"rollback": rollbackInfo(file, backupPath, true),
		}, nil
	}
	return map[string]any{"ok": true, "file": file, "backup": backupPath}, nil
}

// backupSiteConf copies file into siteBackupDir with a timestamped name,
// creating the backup dir (0600) if needed. Returns the backup path.
func backupSiteConf(ctx context.Context, file string) (string, error) {
	if err := os.MkdirAll(siteBackupDir, 0600); err != nil {
		return "", err
	}
	base := filepath.Base(file)
	ts := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(siteBackupDir, base+".bak-"+ts)
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, b, 0600); err != nil {
		return "", err
	}
	return dest, nil
}

// rollbackSiteConf restores the backup (or removes a newly-created file).
func rollbackSiteConf(ctx context.Context, file, backupPath string, hadExisting bool) {
	if hadExisting && backupPath != "" {
		_ = os.Rename(backupPath, file)
		return
	}
	if !hadExisting {
		_ = os.Remove(file)
	}
}

// rollbackInfo describes what was rolled back (for the response).
func rollbackInfo(file, backupPath string, hadExisting bool) map[string]any {
	if hadExisting {
		return map[string]any{"restored": backupPath}
	}
	return map[string]any{"removed": file}
}

// nginxTestInContainer runs `nginx -t` inside the fixed nginx container.
// It returns (ok, boundedOutput). Never panics on container absence.
func nginxTestInContainer(ctx context.Context) (bool, string) {
	out, err := exec.CommandContext(ctx, "docker", "exec", nginxContainer, "nginx", "-t").CombinedOutput()
	if err != nil {
		return false, boundedNginxOutput(out, err)
	}
	return true, strings.TrimSpace(string(out))
}

// nginxReloadInContainer runs `nginx -s reload`; returns "" on success or the
// bounded error output.
func nginxReloadInContainer(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "docker", "exec", nginxContainer, "nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return boundedNginxOutput(out, err)
	}
	return ""
}
