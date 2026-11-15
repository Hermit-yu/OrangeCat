package actions

import (
	"context"
	"testing"
)

// TestComposeProjectsRejectsParameters pins the discovery action is read-only.
func TestComposeProjectsRejectsParameters(t *testing.T) {
	if _, err := ComposeProjects(context.Background(), map[string]any{"path": "/etc"}); err == nil {
		t.Fatal("compose.projects must reject parameters")
	}
}

// TestComposeValidateRejectsUnknownPath is the security boundary: the panel must
// never be able to ask the agent to validate a compose file outside the fixed
// roots, because compose files routinely carry secrets and this endpoint must not
// become a generic read-any-file channel.
func TestComposeValidateRejectsUnknownPath(t *testing.T) {
	for _, path := range []string{
		"", "/etc/passwd", "/root/.ssh/id_rsa", "/home/web/docker-compose1.yml",
		"../docker-compose.yml", "/opt/horizon/../../etc/passwd",
	} {
		if _, err := ComposeValidate(context.Background(), map[string]any{"path": path}); err == nil {
			t.Errorf("path %q must be refused", path)
		}
	}
}

// TestComposeValidateAcceptsKnownPath verifies a known project file passes the
// allowlist check (it may still fail docker compose config on a host without the
// file, but must not be refused at the boundary).
func TestComposeValidateAcceptsKnownPath(t *testing.T) {
	for _, path := range []string{"/home/web/docker-compose.yml", "/opt/horizon/docker-compose.yml"} {
		if !isKnownComposePath(path) {
			t.Errorf("known path %q must be accepted by the allowlist", path)
		}
	}
}

// TestComposeValidateRejectsExtraParams keeps the write-adjacent surface closed.
func TestComposeValidateRejectsExtraParams(t *testing.T) {
	if _, err := ComposeValidate(context.Background(), map[string]any{"path": "/opt/horizon/docker-compose.yml", "extra": "x"}); err == nil {
		t.Fatal("compose.validate must reject unknown parameters")
	}
}
