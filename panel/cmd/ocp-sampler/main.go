// Command ocp-sampler samples read-only host metrics through the ocp-agent
// socket every interval and stores them in SQLite history.
//
// Sample storage: /var/lib/ocp/metrics.db (WAL, schema v1).
// Retention: raw samples 30 days; hourly rollups 12 months.
// The sampler is read-only against the host: every metric comes from the agent's
// whitelisted read actions (system.metrics, net.interfaces).
package main

import (
	"flag"
	"log"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/history"
)

func main() {
	sock := flag.String("socket", "/run/ocp/agent.sock", "ocp-agent unix socket")
	dbPath := flag.String("db", "/var/lib/ocp/metrics.db", "SQLite history database path")
	intervalSec := flag.Int("interval", 30, "sampling interval in seconds")
	flag.Parse()

	if *intervalSec < 5 || *intervalSec > 3600 {
		log.Fatalf("interval must be between 5 and 3600 seconds")
	}
	interval := time.Duration(*intervalSec) * time.Second

	store, err := history.Open(*dbPath)
	if err != nil {
		log.Fatalf("open history: %v", err)
	}
	defer store.Close()

	client := agentbridge.New(*sock)

	var lastNetRX, lastNetTX int64
	haveLast := false
	lastRollupTo := int64(0)
	lastPrune := time.Now()

	for {
		start := time.Now()
		ts := start.Unix()

		metrics, err := client.Call("system.metrics", nil)
		if err != nil {
			log.Printf("system.metrics failed: %v", err)
			time.Sleep(interval)
			continue
		}
		sm := history.Sample{Ts: ts}
		if v, ok := num(metrics, "cpu_percent"); ok {
			sm.CPU = v
		}
		if v, ok := num(metrics, "mem_used_percent"); ok {
			sm.Mem = v
		}
		if v, ok := num(metrics, "disk_used_percent"); ok {
			sm.Disk = v
		}
		if v, ok := num(metrics, "swap_used_percent"); ok {
			sm.Swap = v
		}
		if v, ok := num(metrics, "load_1m"); ok {
			sm.Load1 = v
		}
		if v, ok := num(metrics, "load_5m"); ok {
			sm.Load5 = v
		}
		if v, ok := num(metrics, "load_15m"); ok {
			sm.Load15 = v
		}

		net, err := client.Call("net.interfaces", nil)
		if err == nil {
			rx, tx := totalRXTX(net)
			if haveLast && interval > 0 {
				if rx >= lastNetRX {
					sm.NetRxBps = float64(rx-lastNetRX) / interval.Seconds()
				}
				if tx >= lastNetTX {
					sm.NetTxBps = float64(tx-lastNetTX) / interval.Seconds()
				}
			}
			lastNetRX, lastNetTX, haveLast = rx, tx, true
		}

		if err := store.InsertSample(sm); err != nil {
			log.Printf("insert sample: %v", err)
		}

		// Hourly rollup: aggregate every completed hour up to the current hour.
		thisHour := ts / 3600 * 3600
		if lastRollupTo == 0 {
			lastRollupTo = thisHour
		} else if thisHour > lastRollupTo {
			if n, err := store.RollupWindow(lastRollupTo, thisHour); err != nil {
				log.Printf("rollup %d..%d: %v", lastRollupTo, thisHour, err)
			} else if n > 0 {
				log.Printf("rollup wrote %d hourly rows", n)
			}
			lastRollupTo = thisHour
		}

		// Daily retention prune (raw 30d, hourly 12mo).
		if time.Since(lastPrune) >= 24*time.Hour {
			now := time.Now().Unix()
			dS, dH, err := store.Prune(now-30*86400, now-370*86400)
			if err != nil {
				log.Printf("prune: %v", err)
			} else if dS > 0 || dH > 0 {
				log.Printf("pruned %d samples, %d hourly rows", dS, dH)
			}
			lastPrune = time.Now()
		}

		// Sample the clock for the seconds remaining: align to interval boundaries.
		elapsed := time.Since(start)
		wait := interval - elapsed
		if wait < time.Second {
			wait = time.Second
		}
		time.Sleep(wait)
	}
}

// num extracts a float64 field from agent JSON data.
func num(data map[string]any, key string) (float64, bool) {
	v, ok := data[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return f, true
}

// totalRXTX sums rx/tx bytes across non-loopback interfaces.
func totalRXTX(data map[string]any) (int64, int64) {
	ifaces, ok := data["interfaces"].([]any)
	if !ok {
		return 0, 0
	}
	var rx, tx int64
	for _, raw := range ifaces {
		ifc, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := ifc["name"].(string); ok && name == "lo" {
			continue
		}
		if v, ok := ifc["rx_bytes"].(float64); ok {
			rx += int64(v)
		}
		if v, ok := ifc["tx_bytes"].(float64); ok {
			tx += int64(v)
		}
	}
	return rx, tx
}
