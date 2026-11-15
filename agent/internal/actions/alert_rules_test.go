package actions

import "testing"

// TestBreach: operator semantics.
func TestBreach(t *testing.T) {
	cases := []struct {
		val, th float64
		op      string
		want    bool
	}{
		{95, 90, ">", true},
		{90, 90, ">", false},
		{90, 90, ">=", true},
		{10, 20, "<", true},
		{20, 20, "<=", true},
		{21, 20, "<=", false},
	}
	for _, c := range cases {
		if got := breach(c.val, c.op, c.th); got != c.want {
			t.Fatalf("breach(%g,%s,%g) = %v, want %v", c.val, c.op, c.th, got, c.want)
		}
	}
}

// TestCooldownDuration: default 5m, valid parse, invalid -> 5m.
func TestCooldownDuration(t *testing.T) {
	if d := cooldownDuration(""); d != 5*60*1e9 {
		t.Fatalf("default = %v, want 5m", d)
	}
	if d := cooldownDuration("30s"); d != 30*1e9 {
		t.Fatalf("30s = %v", d)
	}
	if d := cooldownDuration("bogus"); d != 5*60*1e9 {
		t.Fatalf("bogus should default to 5m, got %v", d)
	}
}
