package history

import (
	"path/filepath"
	"testing"
	"time"
)

func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInsertAndQuerySamples(t *testing.T) {
	s := mustOpen(t)
	base := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC).Unix()
	for i := 0; i < 5; i++ {
		sm := Sample{Ts: base + int64(i*30), CPU: 10 + float64(i), Mem: 50, Disk: 20, Swap: 5, Load1: 1, Load5: 1, Load15: 1, NetRxBps: 1000, NetTxBps: 2000}
		if err := s.InsertSample(sm); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
	}
	got, err := s.QuerySamples(base, base+120)
	if err != nil {
		t.Fatalf("QuerySamples: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d samples, want 5", len(got))
	}
	if got[0].CPU != 10 || got[4].CPU != 14 {
		t.Fatalf("unexpected cpu values: %v %v", got[0].CPU, got[4].CPU)
	}
	// out-of-range filtering
	got, _ = s.QuerySamples(base+30, base+60)
	if len(got) != 2 {
		t.Fatalf("range filter: got %d, want 2", len(got))
	}
}

func TestUpsertSameSecond(t *testing.T) {
	s := mustOpen(t)
	ts := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if err := s.InsertSample(Sample{Ts: ts, CPU: float64(i), Mem: 1, Disk: 1, Swap: 1, Load1: 1, Load5: 1, Load15: 1}); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
	}
	got, err := s.QuerySamples(ts, ts)
	if err != nil {
		t.Fatalf("QuerySamples: %v", err)
	}
	if len(got) != 1 || got[0].CPU != 2 {
		t.Fatalf("upsert failed: len=%d cpu=%v", len(got), got[0].CPU)
	}
}

func TestRollupWindowBoundaries(t *testing.T) {
	s := mustOpen(t)
	// 10:00:00..10:59:30 → hour 10; 11:00:00..11:29:30 → hour 11. Include the exact hour boundary.
	hour10 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC).Unix()
	hour11 := time.Date(2026, 11, 15, 11, 0, 0, 0, time.UTC).Unix()
	samples := []Sample{
		{Ts: hour10, CPU: 10, Mem: 50, Disk: 20, Swap: 5, Load1: 1, Load5: 1, Load15: 1, NetRxBps: 100, NetTxBps: 200},
		{Ts: hour10 + 1800, CPU: 20, Mem: 60, Disk: 20, Swap: 5, Load1: 1, Load5: 1, Load15: 1, NetRxBps: 300, NetTxBps: 400},
		{Ts: hour11, CPU: 30, Mem: 70, Disk: 20, Swap: 5, Load1: 1, Load5: 1, Load15: 1, NetRxBps: 500, NetTxBps: 600},
	}
	for i, sm := range samples {
		if err := s.InsertSample(sm); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	n, err := s.RollupWindow(hour10, hour11+3600)
	if err != nil {
		t.Fatalf("RollupWindow: %v", err)
	}
	if n != 2 {
		t.Fatalf("rollup wrote %d rows, want 2", n)
	}
	rows, err := s.QueryHourly(hour10, hour11)
	if err != nil {
		t.Fatalf("QueryHourly: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("hourly rows %d, want 2", len(rows))
	}
	if rows[0].AvgCPU != 15 || rows[0].MaxCPU != 20 || rows[0].SampleCount != 2 {
		t.Fatalf("hour10 unexpected: avg=%v max=%v count=%d", rows[0].AvgCPU, rows[0].MaxCPU, rows[0].SampleCount)
	}
	if rows[1].AvgCPU != 30 || rows[1].SampleCount != 1 {
		t.Fatalf("hour11 unexpected: avg=%v count=%d", rows[1].AvgCPU, rows[1].SampleCount)
	}
	// re-rollup idempotent (upsert, same values)
	n2, err := s.RollupWindow(hour10, hour11+3600)
	if err != nil || n2 != 2 {
		t.Fatalf("second rollup: n=%d err=%v", n2, err)
	}
	rows, _ = s.QueryHourly(hour10, hour11)
	if len(rows) != 2 || rows[0].AvgCPU != 15 {
		t.Fatalf("re-rollup changed data: %+v", rows)
	}
}

func TestPruneRetention(t *testing.T) {
	s := mustOpen(t)
	now := time.Now().Unix()
	// one far-expired sample (hourly row older than retention, sample older than 30d),
	// one expired sample (older than 30d), two kept samples.
	oldHours := now - 400*86400
	for _, ts := range []int64{oldHours, now - 40*86400, now - 29*86400, now - 10*86400} {
		if err := s.InsertSample(Sample{Ts: ts, CPU: 1, Mem: 1, Disk: 1, Swap: 1, Load1: 1, Load5: 1, Load15: 1}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// rollup builds hourly rows for exactly the sample hours that exist
	if _, err := s.RollupWindow(oldHours, now); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	dSamples, dHours, err := s.Prune(now-30*86400, now-370*86400)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if dSamples != 2 {
		t.Fatalf("pruned %d samples, want 2", dSamples)
	}
	if dHours != 1 {
		t.Fatalf("pruned %d hourly rows, want 1", dHours)
	}
	got, _ := s.QuerySamples(0, now)
	if len(got) != 2 {
		t.Fatalf("after prune %d samples, want 2", len(got))
	}
}

func TestReopenReadsBackData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ts := time.Now().Unix()
	if err := s.InsertSample(Sample{Ts: ts, CPU: 42.5, Mem: 60, Disk: 30, Swap: 5, Load1: 1, Load5: 1, Load15: 1, NetRxBps: 777, NetTxBps: 888}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// simulate process restart: reopen same file
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, err := s2.QuerySamples(ts, ts)
	if err != nil || len(got) != 1 {
		t.Fatalf("reopen query: len=%d err=%v", len(got), err)
	}
	if got[0].CPU != 42.5 || got[0].NetRxBps != 777 {
		t.Fatalf("reopen data mismatch: %+v", got[0])
	}
	latest, err := s2.LatestSampleTs()
	if err != nil || latest != ts {
		t.Fatalf("latest ts: %d err=%v", latest, err)
	}
}
