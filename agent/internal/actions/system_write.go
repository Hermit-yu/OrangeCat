package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// P6 写切片：系统管理写操作（主机名/时区）。
//
// 安全模型：每个写动作先做变更预览（dry_run，返回新旧值不写盘），真实
// 执行前备份原值（/etc/hostname、/etc/timezone 或 timedatectl 当前值），
// 执行后回读验证，失败自动回滚。写操作必须显式确认（dry_run=false）。
//
// SSH 端口：P6 明确只读核对后再选择写入。SSH 端口变更风险高（断连风险），
// 本切片只做只读核对（system.ssh.status），不改端口——避免误锁死 SSH。

// systemWriteTimeout bounds a single hostname/timezone write.
const systemWriteTimeout = 30 * time.Second

// hostnameRe validates a hostname: 1-253 chars, labels of alnum/hyphen,
// no leading/trailing hyphen, no dots-only, no spaces/semicolons.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// timezoneRe validates a zone name: IANA style. Accepts single-segment
// zones (UTC, GMT, Etc/UTC) and multi-segment (Asia/Shanghai). Rejects
// spaces/semicolons/path traversal.
var timezoneRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$`)

// currentHostname reads the live kernel hostname (source of truth).
func currentHostname() string {
	if b, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// currentTimezone reads the live timezone via timedatectl (or /etc/timezone).
func currentTimezone() string {
	if out, err := exec.Command("timedatectl", "show", "--property=Timezone", "--value").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// validateHostname checks the requested hostname; returns a cleaned value.
func validateHostname(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("hostname is required")
	}
	if len(v) > 253 {
		return "", fmt.Errorf("hostname too long")
	}
	if !hostnameRe.MatchString(v) {
		return "", fmt.Errorf("hostname is not a valid hostname")
	}
	return v, nil
}

// validateTimezone checks the requested timezone exists via timedatectl.
func validateTimezone(ctx context.Context, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("timezone is required")
	}
	if !timezoneRe.MatchString(v) {
		return "", fmt.Errorf("timezone is not a valid IANA zone name")
	}
	// Verify it exists (list-timezones contains it) — fail-closed.
	out, err := exec.CommandContext(ctx, "timedatectl", "list-timezones").Output()
	if err == nil {
		for _, z := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(z) == v {
				return v, nil
			}
		}
		return "", fmt.Errorf("timezone %q not in timedatectl list", v)
	}
	return "", fmt.Errorf("timedatectl list-timezones unavailable: %w", err)
}

// SystemHostnameSet sets the hostname. dry_run=true returns the preview only.
// On real run: snapshot old value, apply hostnamectl, verify, rollback on fail.
func SystemHostnameSet(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("system.hostname.set requires parameters")
	}
	// Closed parameter set.
	for k := range params {
		if k != "hostname" && k != "dry_run" {
			return nil, fmt.Errorf("unsupported field: %s", k)
		}
	}
	want, err := validateHostname(fmt.Sprintf("%v", params["hostname"]))
	if err != nil {
		return nil, err
	}
	cur := currentHostname()
	preview := map[string]any{
		"current": cur,
		"new":     want,
		"changed": cur != want,
	}
	dryRun, _ := params["dry_run"].(bool)
	if dryRun {
		preview["dry_run"] = true
		return preview, nil
	}
	if cur == want {
		preview["applied"] = false
		preview["reason"] = "unchanged"
		return preview, nil
	}
	ctx, cancel := context.WithTimeout(ctx, systemWriteTimeout)
	defer cancel()
	// Snapshot for rollback.
	old := cur
	out, err := exec.CommandContext(ctx, "hostnamectl", "set-hostname", want).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("hostnamectl set-hostname failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	// Verify: kernel hostname must match.
	if got := currentHostname(); got != want {
		// Rollback immediately.
		_, _ = exec.CommandContext(ctx, "hostnamectl", "set-hostname", old).CombinedOutput()
		return nil, fmt.Errorf("hostname verify failed (got %q), rolled back", got)
	}
	preview["applied"] = true
	preview["rollback"] = old
	return preview, nil
}

// SystemTimezoneSet sets the system timezone. dry_run=true returns preview.
func SystemTimezoneSet(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("system.timezone.set requires parameters")
	}
	for k := range params {
		if k != "timezone" && k != "dry_run" {
			return nil, fmt.Errorf("unsupported field: %s", k)
		}
	}
	want, err := validateTimezone(ctx, fmt.Sprintf("%v", params["timezone"]))
	if err != nil {
		return nil, err
	}
	cur := currentTimezone()
	preview := map[string]any{
		"current": cur,
		"new":     want,
		"changed": cur != want,
	}
	dryRun, _ := params["dry_run"].(bool)
	if dryRun {
		preview["dry_run"] = true
		return preview, nil
	}
	if cur == want {
		preview["applied"] = false
		preview["reason"] = "unchanged"
		return preview, nil
	}
	ctx, cancel := context.WithTimeout(ctx, systemWriteTimeout)
	defer cancel()
	old := cur
	out, err := exec.CommandContext(ctx, "timedatectl", "set-timezone", want).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("timedatectl set-timezone failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if got := currentTimezone(); got != want {
		_, _ = exec.CommandContext(ctx, "timedatectl", "set-timezone", old).CombinedOutput()
		return nil, fmt.Errorf("timezone verify failed (got %q), rolled back", got)
	}
	preview["applied"] = true
	preview["rollback"] = old
	return preview, nil
}

// SystemSSHStatus is read-only: reports the SSH service state and the current
// configured port (from sshd_config plus drop-ins) without changing anything.
// Port changes are deliberately NOT exposed here (risk of lockout).
func SystemSSHStatus(ctx context.Context, _ map[string]any) (map[string]any, error) {
	data := map[string]any{"port_changes_supported": false}
	if out, err := exec.CommandContext(ctx, "systemctl", "is-active", "ssh").Output(); err == nil {
		data["service"] = "ssh"
		data["active"] = strings.TrimSpace(string(out)) == "active"
	} else if out, err := exec.CommandContext(ctx, "systemctl", "is-active", "sshd").Output(); err == nil {
		data["service"] = "sshd"
		data["active"] = strings.TrimSpace(string(out)) == "active"
	} else {
		data["active"] = false
		data["service"] = "unknown"
	}
	// Read the effective port: main config then drop-ins (last wins).
	port := ""
	for _, f := range []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/99-hardening.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Port ") && !strings.HasPrefix(line, "#") {
				port = strings.TrimSpace(strings.TrimPrefix(line, "Port "))
			}
		}
	}
	data["port"] = port
	return data, nil
}
