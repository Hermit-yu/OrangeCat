package actions

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Cron manages the local root crontab. This is a fixed single source (no path
// parameter can redirect it to another user's crontab or to a file). Write
// actions reinstall the whole crontab from an in-memory copy, so a malformed
// line is rejected before anything is written back.
var (
	cronMaxLines = 500
	cronMaxLen   = 1000
)

type cronJob struct {
	Index    int    `json:"index"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Comment  string `json:"comment"`
	Enabled  bool   `json:"enabled"`
}

func getCrontab(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "crontab", "-l").Output()
	if err != nil {
		// An empty crontab is a normal state, not an error.
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no crontab") || strings.Contains(msg, "exit status 1") {
			return "", nil
		}
		return "", err
	}
	return string(out), nil
}

// parseCrontab splits raw crontab content into indexed jobs. Only user cron
// entries (5 schedule fields + command) are listed; ENV lines like
// PATH=/usr/bin are kept as-is but not offered for edit/remove through the
// panel because removing them can break the rest of the crontab.
func parseCrontab(raw string) []cronJob {
	var jobs []cronJob
	idx := 0
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		isComment := strings.HasPrefix(strings.TrimSpace(line), "#")
		if isComment {
			// A commented cron line is an easy way to "disable" a task.
			body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
			if body == "" {
				continue
			}
			jobs = append(jobs, cronJob{Index: idx, Command: body, Comment: strings.TrimSpace(line), Enabled: false})
			idx++
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			// ENV line or malformed — keep visible so the panel shows reality,
			// but flag it disabled: it is not a schedulable task and must not be
			// presented as one.
			jobs = append(jobs, cronJob{Index: idx, Command: strings.TrimSpace(line), Enabled: false})
			idx++
			continue
		}
		sched := strings.Join(fields[:5], " ")
		cmd := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), sched))
		jobs = append(jobs, cronJob{Index: idx, Schedule: sched, Command: cmd, Enabled: true})
		idx++
	}
	return jobs
}

func listCron(ctx context.Context, _ map[string]any) (map[string]any, error) {
	raw, err := getCrontab(ctx)
	if err != nil {
		return nil, err
	}
	jobs := parseCrontab(raw)
	return map[string]any{
		"count":  len(jobs),
		"jobs":   jobs,
		"source": "root_crontab",
	}, nil
}

func noParamsCronList(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		if key != "" {
			return nil, fmt.Errorf("cron.list accepts no parameters")
		}
	}
	return listCron(ctx, p)
}

// validateCronLine enforces closed-form input before a write. We reject
// carriage returns, NUL bytes and overlong lines to keep the crontab file
// well-formed; we do not shell-eval anything here.
func validateCronLine(line string) error {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return fmt.Errorf("line is required")
	}
	if len(trimmed) > cronMaxLen {
		return fmt.Errorf("line too long")
	}
	for _, r := range trimmed {
		switch {
		case r == '\r' || r == 0:
			return fmt.Errorf("line contains forbidden character")
		case r < 32 && r != '	':
			return fmt.Errorf("line contains forbidden control character")
		}
	}
	return nil
}

// readCrontabLines returns the non-empty lines of the current crontab, with
// their original order preserved.
func readCrontabLines(ctx context.Context) ([]string, error) {
	raw, err := getCrontab(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func writeCrontab(ctx context.Context, lines []string) error {
	if len(lines) > cronMaxLines {
		return fmt.Errorf("crontab too large to rewrite")
	}
	payload := strings.Join(lines, "\n") + "\n"
	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

func validateCronParams(p map[string]any, allow map[string]bool) error {
	for key := range p {
		if !allow[key] {
			return fmt.Errorf("unknown parameter %q", key)
		}
	}
	return nil
}

// CronAdd appends one cron line to the root crontab.
func CronAdd(ctx context.Context, p map[string]any) (map[string]any, error) {
	if err := validateCronParams(p, map[string]bool{"line": true}); err != nil {
		return nil, err
	}
	line, ok := p["line"].(string)
	if !ok {
		return nil, fmt.Errorf("line must be a string")
	}
	line = strings.TrimSpace(line)
	if err := validateCronLine(line); err != nil {
		return nil, err
	}
	lines, err := readCrontabLines(ctx)
	if err != nil {
		return nil, err
	}
	// Refuse exact duplicates so a UI double-click cannot pile up entries.
	for _, existing := range lines {
		if strings.TrimSpace(existing) == strings.TrimSpace(line) {
			return nil, fmt.Errorf("identical cron line already exists")
		}
	}
	lines = append(lines, line)
	if err := writeCrontab(ctx, lines); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "added": line}, nil
}

// CronRemove deletes the cron line at the given 0-based index. The index is
// re-derived from a fresh read, so a stale UI list cannot delete the wrong
// line after a concurrent edit.
func CronRemove(ctx context.Context, p map[string]any) (map[string]any, error) {
	if err := validateCronParams(p, map[string]bool{"index": true}); err != nil {
		return nil, err
	}
	idx, err := cronIndexParam(p)
	if err != nil {
		return nil, err
	}
	lines, err := readCrontabLines(ctx)
	if err != nil {
		return nil, err
	}
	if idx < 0 || idx >= len(lines) {
		return nil, fmt.Errorf("index out of range")
	}
	removed := lines[idx]
	rest := append(lines[:idx:idx], lines[idx+1:]...)
	if err := writeCrontab(ctx, rest); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "removed": removed}, nil
}

// CronToggle comments/uncomments the cron line at the given index.
func CronToggle(ctx context.Context, p map[string]any) (map[string]any, error) {
	if err := validateCronParams(p, map[string]bool{"index": true}); err != nil {
		return nil, err
	}
	idx, err := cronIndexParam(p)
	if err != nil {
		return nil, err
	}
	lines, err := readCrontabLines(ctx)
	if err != nil {
		return nil, err
	}
	if idx < 0 || idx >= len(lines) {
		return nil, fmt.Errorf("index out of range")
	}
	line := strings.TrimSpace(lines[idx])
	var updated string
	if strings.HasPrefix(line, "#") {
		updated = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	} else {
		updated = "# " + line
	}
	if err := validateCronLine(updated); err != nil {
		return nil, err
	}
	lines[idx] = updated
	if err := writeCrontab(ctx, lines); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "index": idx, "line": updated}, nil
}

func cronIndexParam(p map[string]any) (int, error) {
	switch v := p["index"].(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	}
	return 0, fmt.Errorf("index must be a number")
}
