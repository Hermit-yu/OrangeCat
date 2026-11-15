package actions

import (
	"context"
	"testing"
)

// TestNotifyNoTokenHonest: without credentials, notify actions must return a
// clear "not configured" rather than a fake success.
func TestNotifyNoTokenHonest(t *testing.T) {
	// Ensure env is clear for this test.
	t.Setenv("OCP_AGENT_NOTIFY_TOKEN", "")
	t.Setenv("OCP_AGENT_NOTIFY_CHAT_ID", "")

	st, err := NotifyStatus(context.Background(), nil)
	if err != nil {
		t.Fatalf("status should not error: %v", err)
	}
	if st["enabled"] != false || st["needs_token"] != true {
		t.Fatalf("unexpected status: %+v", st)
	}

	// notify.test without token -> not_configured true (honest).
	res, err := NotifyTest(context.Background(), map[string]any{"message": "test"})
	if err != nil {
		t.Fatalf("test should return structured result, not error: %v", err)
	}
	if res["ok"] != false || res["not_configured"] != true {
		t.Fatalf("test without token should be not_configured, got %+v", res)
	}

	// notify.alert without token -> not_configured true.
	res2, err := NotifyAlert(context.Background(), map[string]any{"severity": "critical", "message": "x"})
	if err != nil {
		t.Fatalf("alert should return structured result, not error: %v", err)
	}
	if res2["ok"] != false || res2["not_configured"] != true {
		t.Fatalf("alert without token should be not_configured, got %+v", res2)
	}
}

// TestNotifyRejectsExtraFields: closed param sets.
func TestNotifyRejectsExtraFields(t *testing.T) {
	t.Setenv("OCP_AGENT_NOTIFY_TOKEN", "")
	t.Setenv("OCP_AGENT_NOTIFY_CHAT_ID", "")
	if _, err := NotifyTest(context.Background(), map[string]any{"message": "x", "extra": "y"}); err == nil {
		t.Fatalf("extra field should be rejected")
	}
	if _, err := NotifyAlert(context.Background(), map[string]any{"severity": "x", "message": "y", "extra": "z"}); err == nil {
		t.Fatalf("extra field should be rejected")
	}
	if _, err := NotifyAlert(context.Background(), map[string]any{"severity": "invalid", "message": "y"}); err == nil {
		t.Fatalf("invalid severity should be rejected")
	}
}
