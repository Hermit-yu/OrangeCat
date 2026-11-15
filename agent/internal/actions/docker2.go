package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// P2: Docker 只读到可管理。
//
// 所有动作只使用固定的 docker 子命令与 --format 模板，用户输入仅作为单个
// exec 参数传入（R3：不经过 shell，无法注入）。名称/参数一律先校验。
// 只读动作绝不接受 action/op 之类的键；写动作见 ContainerAction。

// maxListEntries bounds any list returned to the panel.
const maxListEntries = 500

// maxLogLines caps docker logs tail length so a chatty container cannot
// exhaust the request budget or the response size.
const maxLogLines = 500

// dockerNameRe mirrors docker's own name validation (no leading dash, so an
// argument cannot be mistaken for a flag).
var dockerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func validateDockerName(value, field string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if !dockerNameRe.MatchString(name) {
		return "", fmt.Errorf("%s contains characters docker does not accept", field)
	}
	return name, nil
}

// parseNDJSON decodes docker's `--format` NDJSON output (one object per line,
// not a JSON array). Trailing whitespace is ignored.
func parseNDJSON(raw []byte) []map[string]any {
	var list []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	for {
		var one map[string]any
		if err := dec.Decode(&one); err != nil {
			break
		}
		list = append(list, one)
	}
	if list == nil {
		list = []map[string]any{}
	}
	return list
}

func boundEntries(list []map[string]any) []map[string]any {
	if len(list) > maxListEntries {
		list = list[:maxListEntries]
	}
	return list
}

// DockerImages lists images with size and tag.
func DockerImages(ctx context.Context, _ map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "images", "--format",
		`{"repo":"{{.Repository}}","tag":"{{.Tag}}","size":"{{.Size}}","id":"{{.ID}}"}`).Output()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error(), "images": []map[string]any{}}, nil
	}
	list := boundEntries(parseNDJSON(out))
	return map[string]any{"available": true, "images": list, "count": len(list)}, nil
}

// DockerNetworks lists networks with driver/scope and member containers.
func DockerNetworks(ctx context.Context, _ map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "network", "ls", "--format",
		`{"name":"{{.Name}}","driver":"{{.Driver}}","scope":"{{.Scope}}"}`).Output()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error(), "networks": []map[string]any{}}, nil
	}
	list := boundEntries(parseNDJSON(out))
	// members per network: best-effort, not fatal when a network has none.
	for _, row := range list {
		name, _ := row["name"].(string)
		members := networkMembers(ctx, name)
		row["containers"] = members
	}
	return map[string]any{"available": true, "networks": list, "count": len(list)}, nil
}

// dockerInspectSingle decodes `docker <obj> inspect --format {{json .}}` output.
// That form prints a single OBJECT (not the array `docker inspect` emits without
// --format), so callers must not assume a slice. Returns nil when absent.
func dockerInspectSingle(ctx context.Context, obj, name string) map[string]any {
	mctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(mctx, "docker", obj, "inspect", "--format",
		"{{json .}}", name).Output()
	if err != nil {
		return nil
	}
	var one map[string]any
	if err := json.Unmarshal(out, &one); err != nil {
		return nil
	}
	return one
}

func networkMembers(ctx context.Context, network string) []string {
	if network == "" {
		return []string{}
	}
	info := dockerInspectSingle(ctx, "network", network)
	if info == nil {
		return []string{}
	}
	members, _ := info["Containers"].([]any)
	names := []string{}
	for _, m := range members {
		n, _ := m.(map[string]any)
		if v, _ := n["Name"].(string); v != "" {
			names = append(names, v)
		}
	}
	return names
}

// DockerVolumes lists volumes with driver, mountpoint and using containers.
func DockerVolumes(ctx context.Context, _ map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "volume", "ls", "--format",
		`{"name":"{{.Name}}","driver":"{{.Driver}}","mountpoint":"{{.Mountpoint}}"}`).Output()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error(), "volumes": []map[string]any{}}, nil
	}
	list := boundEntries(parseNDJSON(out))
	for _, row := range list {
		name, _ := row["name"].(string)
		row["used_by"] = volumeUsers(ctx, name)
	}
	return map[string]any{"available": true, "volumes": list, "count": len(list)}, nil
}

// volumeUsers returns container names currently using a volume (best-effort).
// Inspect with `{{json .}}` rather than a field-specific template: newer Docker
// builds drop the Mountpoints key entirely for empty volumes and error out on
// direct field access, so parse the object ourselves.
func volumeUsers(ctx context.Context, volume string) []string {
	if volume == "" {
		return []string{}
	}
	info := dockerInspectSingle(ctx, "volume", volume)
	if info == nil {
		return []string{}
	}
	mounts, _ := info["Mountpoints"].([]any)
	names := []string{}
	for _, m := range mounts {
		n, _ := m.(map[string]any)
		if v, _ := n["Name"].(string); v != "" {
			names = append(names, v)
		}
	}
	return names
}

// DockerLogs returns a bounded tail of a container's logs. Lines are trimmed and
// capped; a truncation flag tells the panel whether more existed.
func DockerLogs(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		switch key {
		case "name", "lines":
		default:
			return nil, fmt.Errorf("docker.logs accepts only name, lines")
		}
	}
	name, err := validateDockerName(mustString(p, "name"), "name")
	if err != nil {
		return nil, err
	}
	lines := maxLogLines
	if v, ok := p["lines"].(float64); ok && v > 0 && v < maxLogLines {
		lines = int(v)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// --no-trunc is rejected by newer Docker releases, so do not pass it.
	out, err := exec.CommandContext(ctx, "docker", "logs", "--tail", fmt.Sprintf("%d", lines),
		"--timestamps", name).CombinedOutput()
	if err != nil {
		return map[string]any{"available": false, "error": dockerErrorText(err, out), "logs": []string{}}, nil
	}
	raw := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	// drop docker's stream headers: "container-id stdout 2026-..."
	filtered := make([]string, 0, len(raw))
	for _, line := range raw {
		if strings.TrimSpace(line) == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	truncated := len(filtered) >= lines
	if len(filtered) > maxLogLines {
		filtered = filtered[len(filtered)-maxLogLines:]
	}
	return map[string]any{
		"available": true, "name": name, "logs": filtered,
		"count": len(filtered), "truncated": truncated,
	}, nil
}

// DockerStats returns a single non-streaming resource reading per container.
func DockerStats(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		if key != "name" {
			return nil, errors.New("docker.stats accepts only name")
		}
	}
	name, err := validateDockerName(mustString(p, "name"), "name")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format",
		`{"name":"{{.Name}}","cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}","mem_limit":"{{.MemPerc}}","net":"{{.NetIO}}","blk":"{{.BlockIO}}"}`,
		name).Output()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error(), "stats": []map[string]any{}}, nil
	}
	list := parseNDJSON(out)
	return map[string]any{"available": true, "stats": list, "count": len(list)}, nil
}

// DockerContainerAction performs a container lifecycle operation. This is the
// only P2 write path: the operation is an explicit closed enum and the target
// must pass docker's name rules, so no arbitrary command is reachable.
// It verifies the container exists first and reports the pre-action state.
func DockerContainerAction(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		switch key {
		case "name", "action":
		default:
			return nil, fmt.Errorf("docker.container.action accepts only name, action")
		}
	}
	name, err := validateDockerName(mustString(p, "name"), "name")
	if err != nil {
		return nil, err
	}
	action := strings.ToUpper(strings.TrimSpace(mustString(p, "action")))
	var dockerSub string
	switch action {
	case "START":
		dockerSub = "start"
	case "STOP":
		dockerSub = "stop"
	case "RESTART":
		dockerSub = "restart"
	case "KILL":
		dockerSub = "kill"
	default:
		return nil, fmt.Errorf("action must be one of START, STOP, RESTART, KILL")
	}
	pre, preState := containerFacts(ctx, name)
	if !pre {
		return map[string]any{"sent": false, "name": name, "action": action, "state": "", "reason": "container not found"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", dockerSub, name).CombinedOutput()
	if err != nil {
		return map[string]any{
			"sent": false, "name": name, "action": action, "state": preState,
			"reason": dockerErrorText(err, out),
		}, nil
	}
	// read back the resulting state so the panel never has to trust the exit code
	post, postState := containerFacts(ctx, name)
	return map[string]any{
		"sent": true, "name": name, "action": action,
		"state": postState, "post_state": postState, "verified": post,
	}, nil
}

// containerFacts returns existence and current state via a fixed subcommand.
func containerFacts(ctx context.Context, name string) (bool, string) {
	mctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(mctx, "docker", "inspect", "--format",
		"{{.State.Running}}|{{.State.Status}}", name).Output()
	if err != nil {
		return false, ""
	}
	part := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	return true, part[1]
}

func mustString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// dockerErrorText surfaces docker's message but never echoes raw args back as a
// command; a bounded length keeps responses small.
func dockerErrorText(err error, out []byte) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// Sort helpers used by callers that want deterministic ordering.
func sortByName(list []map[string]any) {
	sort.Slice(list, func(i, j int) bool {
		a, _ := list[i]["name"].(string)
		b, _ := list[j]["name"].(string)
		return a < b
	})
}
