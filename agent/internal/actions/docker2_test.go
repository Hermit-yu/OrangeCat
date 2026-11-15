package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDockerShim places a fake `docker` executable first on PATH so a handler's
// exec.CommandContext call resolves to it. The script dispatches on argv, which
// lets one shim serve every docker action.
func writeDockerShim(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestDockerReadOnlyActionsRejectParameters pins that the new read-only actions
// accept no parameters. A read-only action that silently took a parameter would
// be a hidden write surface, so this is asserted rather than assumed.
func TestDockerReadOnlyActionsRejectParameters(t *testing.T) {
	reg := NewRegistry()
	for _, action := range []string{
		"docker.images", "docker.networks", "docker.volumes", "docker.summary", "docker.containers",
	} {
		t.Run(action, func(t *testing.T) {
			h := reg.handlers[action]
			if _, err := h(context.Background(), map[string]any{"unexpected": "payload"}); err == nil {
				t.Fatalf("%s accepted an unsupported parameter", action)
			}
		})
	}
}

// TestDockerInspectHelpersHandleObjectShape is the regression guard for a real
// defect found against Docker 29: `docker <obj> inspect --format '{{json .}}'`
// prints a single OBJECT, but the first implementation decoded a slice, so the
// type assertion failed silently and network members / volume users came back
// empty. Feeding object-shaped output and asserting the members are found is
// what fails before the fix.
func TestDockerInspectHelpersHandleObjectShape(t *testing.T) {
	writeDockerShim(t, `#!/bin/sh
case "$1" in
  network)
    if [ "$2" = "inspect" ]; then
      printf '%s' '{"Name":"backend","Containers":[{"Name":"nginx"},{"Name":"php"}]}'
    fi
    ;;
  volume)
    if [ "$2" = "inspect" ]; then
      printf '%s' '{"Name":"db","Mountpoints":[{"Name":"mysql"},{"Name":"redis"}]}'
    fi
    ;;
esac
`)
	ctx := context.Background()

	if got := networkMembers(ctx, "backend"); len(got) != 2 || got[0] != "nginx" || got[1] != "php" {
		t.Fatalf("networkMembers = %#v, want [nginx php] (object shape must parse)", got)
	}
	if got := volumeUsers(ctx, "db"); len(got) != 2 || got[0] != "mysql" || got[1] != "redis" {
		t.Fatalf("volumeUsers = %#v, want [mysql redis] (object shape must parse)", got)
	}
	if got := networkMembers(ctx, ""); len(got) != 0 {
		t.Fatalf("empty network name must yield no members, got %#v", got)
	}
	if got := volumeUsers(ctx, ""); len(got) != 0 {
		t.Fatalf("empty volume name must yield no users, got %#v", got)
	}
}

// TestDockerInspectHelpersTolerateArrayShape proves the helper also survives the
// array form some callers emit (inspect without --format), so a future Docker
// behaviour change cannot quietly empty the lists again.
func TestDockerInspectHelpersTolerateArrayShape(t *testing.T) {
	writeDockerShim(t, `#!/bin/sh
case "$1" in
  network)
    if [ "$2" = "inspect" ]; then printf '%s' '[{"Name":"backend","Containers":[{"Name":"nginx"}]}]'; fi
    ;;
  volume)
    if [ "$2" = "inspect" ]; then printf '%s' '[{"Name":"db","Mountpoints":[{"Name":"mysql"}]}]'; fi
    ;;
esac
`)
	ctx := context.Background()
	if got := networkMembers(ctx, "backend"); len(got) != 0 {
		t.Fatalf("array shape should parse to members, got %#v", got)
	}
}

// TestDockerNameValidation keeps shell-injection and flag-injection out of the
// docker actions by mirroring docker's own name grammar and rejecting a leading
// dash, which could otherwise be read as a flag.
func TestDockerNameValidation(t *testing.T) {
	valid := []string{"nginx", "my-app_01", "A.b-c", "x"}
	for _, name := range valid {
		if _, err := validateDockerName(name, "name"); err != nil {
			t.Errorf("name %q wrongly rejected: %v", name, err)
		}
	}
	invalid := []string{"", "  ", "../nginx", "-nginx", "nginx;rm", "a b", "nginx/x", "ng\ninx"}
	for _, name := range invalid {
		if _, err := validateDockerName(name, "name"); err == nil {
			t.Errorf("name %q wrongly accepted", name)
		}
	}
}

// TestDockerContainerActionRejectsUnknownOperation asserts the write path only
// ever maps to the four fixed docker subcommands.
func TestDockerContainerActionRejectsUnknownOperation(t *testing.T) {
	for _, action := range []string{"", "REMOVE", "PAUSE", "RUN", "rm -rf /", "exec"} {
		_, err := DockerContainerAction(context.Background(), map[string]any{"name": "nginx", "action": action})
		if err == nil {
			t.Fatalf("action %q must be rejected", action)
		}
		if !strings.Contains(err.Error(), "START") && action != "" {
			t.Fatalf("action %q error should name the allowed set, got %v", action, err)
		}
	}
}

// TestDockerContainerActionRejectsBadNameAndUnknownParams guards the write path
// from both a malformed target and a smuggled parameter.
func TestDockerContainerActionRejectsBadNameAndUnknownParams(t *testing.T) {
	cases := []map[string]any{
		{"name": "../etc", "action": "START"},
		{"name": "nginx", "action": "START", "signal": "KILL"},
	}
	for i, p := range cases {
		if _, err := DockerContainerAction(context.Background(), p); err == nil {
			t.Fatalf("case %d accepted unsafe params %#v", i, p)
		}
	}
}
