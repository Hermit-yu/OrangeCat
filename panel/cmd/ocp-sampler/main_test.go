package main

import "testing"

func TestTotalRXTXSumsNonLoopback(t *testing.T) {
	data := map[string]any{
		"interfaces": []any{
			map[string]any{"name": "lo", "rx_bytes": float64(99999), "tx_bytes": float64(99999)},
			map[string]any{"name": "eth0", "rx_bytes": float64(1000), "tx_bytes": float64(2000)},
			map[string]any{"name": "eth1", "rx_bytes": float64(3000), "tx_bytes": float64(4000)},
		},
	}
	rx, tx := totalRXTX(data)
	if rx != 4000 {
		t.Fatalf("rx=%d want 4000", rx)
	}
	if tx != 6000 {
		t.Fatalf("tx=%d want 6000", tx)
	}
}

func TestTotalRXTXDegradesGracefully(t *testing.T) {
	for name, data := range map[string]map[string]any{
		"missing interfaces": {},
		"bad items":          {"interfaces": []any{"not a map", map[string]any{}}},
		"typed numbers":      {"interfaces": []any{map[string]any{"name": "eth0", "rx_bytes": int64(5)}}},
	} {
		t.Run(name, func(t *testing.T) {
			rx, tx := totalRXTX(data)
			if rx != 0 || tx != 0 {
				t.Fatalf("rx=%d tx=%d want 0 0", rx, tx)
			}
		})
	}
}

func TestNumExtractsFloat(t *testing.T) {
	if v, ok := num(map[string]any{"cpu_percent": float64(12.5)}, "cpu_percent"); !ok || v != 12.5 {
		t.Fatalf("num float: v=%v ok=%v", v, ok)
	}
	if _, ok := num(map[string]any{}, "missing"); ok {
		t.Fatal("num missing key must be !ok")
	}
	if _, ok := num(map[string]any{"x": "string"}, "x"); ok {
		t.Fatal("num wrong type must be !ok")
	}
}
