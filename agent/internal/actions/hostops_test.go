package actions

import (
	"context"
	"testing"
)

func TestParseDFOutput(t *testing.T) {
	gotTotal, gotUsed, err := parseDFOutput("1B-blocks        Used       Avail\n51835101184 37112725504 14705598464\n")
	if err != nil {
		t.Fatalf("parseDFOutput returned error: %v", err)
	}
	if gotTotal != 51835101184 || gotUsed != 37112725504 {
		t.Fatalf("unexpected disk values: total=%d used=%d", gotTotal, gotUsed)
	}
}

func TestParseDFOutputRejectsInvalidShape(t *testing.T) {
	for _, input := range []string{"", "df: field 'total' unknown", "header\n1 2\n"} {
		if _, _, err := parseDFOutput(input); err == nil {
			t.Errorf("expected parse error for %q", input)
		}
	}
}

func TestNewRegistryRejectsParametersForReadOnlyActions(t *testing.T) {
	reg := NewRegistry()
	for _, action := range []string{"system.info", "system.metrics", "docker.summary", "docker.containers", "nginx.sites", "net.interfaces"} {
		t.Run(action, func(t *testing.T) {
			h := reg.handlers[action]
			if _, err := h(context.Background(), map[string]any{"unexpected": "payload"}); err == nil {
				t.Fatalf("%s accepted an unsupported parameter", action)
			}
		})
	}
}

func TestProcessesRejectsOutOfRangeAndUnknownParameters(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"negative":     {"top": float64(-1)},
		"too large":    {"top": float64(101)},
		"fractional":   {"top": float64(1.5)},
		"wrong type":   {"top": "20"},
		"unknown":      {"top": float64(20), "path": "/etc/passwd"},
		"unknown only": {"path": "/etc/passwd"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Processes(context.Background(), params); err == nil {
				t.Fatalf("Processes(%v) accepted invalid parameters", params)
			}
		})
	}
}
