// Package history stores time-series host metrics in SQLite.
// Raw samples: 30 days retained. Hourly rollups: 12 months retained.
// Rules: metrics are real host readings; SQLite holds only history (RULES.md).
package history

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

// Sample is one point of host metric history.
type Sample struct {
	Ts       int64 // unix seconds
	CPU      float64
	Mem      float64
	Disk     float64
	Swap     float64
	Load1    float64
	Load5    float64
	Load15   float64
	NetRxBps float64
	NetTxBps float64
}

// HourRow is one hourly rollup row.
type HourRow struct {
	HourTs      int64 // floor(ts/3600)*3600
	SampleCount int
	AvgCPU      float64
	MaxCPU      float64
	AvgMem      float64
	MaxMem      float64
	AvgDisk     float64
	AvgSwap     float64
	AvgLoad1    float64
	NetRxTotal  float64
	NetTxTotal  float64
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the metrics database and applies schema v1.
// parent dir must exist and be writable.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Concurrency: sampler writes, panel reads. WAL is the sane default.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	var ver int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&ver)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if ver > schemaVersion {
		return fmt.Errorf("database schema %d newer than binary schema %d", ver, schemaVersion)
	}
	if ver < 1 {
		if err := s.applyV1(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyV1() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()

	statements := []string{
		`CREATE TABLE IF NOT EXISTS metrics_samples (
			ts INTEGER PRIMARY KEY,
			cpu_percent REAL NOT NULL,
			mem_percent REAL NOT NULL,
			disk_percent REAL NOT NULL,
			swap_percent REAL NOT NULL,
			load_1m REAL NOT NULL,
			load_5m REAL NOT NULL,
			load_15m REAL NOT NULL,
			net_rx_bps REAL NOT NULL DEFAULT 0,
			net_tx_bps REAL NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS metrics_hourly (
			hour_ts INTEGER PRIMARY KEY,
			sample_count INTEGER NOT NULL,
			avg_cpu REAL NOT NULL,
			max_cpu REAL NOT NULL,
			avg_mem REAL NOT NULL,
			max_mem REAL NOT NULL,
			avg_disk REAL NOT NULL,
			avg_swap REAL NOT NULL,
			avg_load1 REAL NOT NULL,
			net_rx_total REAL NOT NULL DEFAULT 0,
			net_tx_total REAL NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_ts ON metrics_samples (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_hourly_ts ON metrics_hourly (hour_ts)`,
	}
	for _, stmt := range statements {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("apply v1 statement: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

var insertSampleSQL = `INSERT INTO metrics_samples
	(ts, cpu_percent, mem_percent, disk_percent, swap_percent, load_1m, load_5m, load_15m, net_rx_bps, net_tx_bps)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT (ts) DO UPDATE SET
		cpu_percent=excluded.cpu_percent, mem_percent=excluded.mem_percent,
		disk_percent=excluded.disk_percent, swap_percent=excluded.swap_percent,
		load_1m=excluded.load_1m, load_5m=excluded.load_5m, load_15m=excluded.load_15m,
		net_rx_bps=excluded.net_rx_bps, net_tx_bps=excluded.net_tx_bps`

// InsertSample stores one raw sample (upsert on same second).
func (s *Store) InsertSample(sm Sample) error {
	_, err := s.db.Exec(insertSampleSQL,
		sm.Ts, sm.CPU, sm.Mem, sm.Disk, sm.Swap, sm.Load1, sm.Load5, sm.Load15, sm.NetRxBps, sm.NetTxBps)
	if err != nil {
		return fmt.Errorf("insert sample: %w", err)
	}
	return nil
}

// QuerySamples returns raw samples in [from, to] ascending.
func (s *Store) QuerySamples(from, to int64) ([]Sample, error) {
	rows, err := s.db.Query(`SELECT ts, cpu_percent, mem_percent, disk_percent, swap_percent,
		load_1m, load_5m, load_15m, net_rx_bps, net_tx_bps
		FROM metrics_samples WHERE ts >= ? AND ts <= ? ORDER BY ts ASC`, from, to)
	if err != nil {
		return nil, fmt.Errorf("query samples: %w", err)
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.Ts, &s.CPU, &s.Mem, &s.Disk, &s.Swap, &s.Load1, &s.Load5, &s.Load15, &s.NetRxBps, &s.NetTxBps); err != nil {
			return nil, fmt.Errorf("scan sample: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LatestSampleTs returns the most recent sample timestamp, or 0 if none.
func (s *Store) LatestSampleTs() (int64, error) {
	var ts sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(ts) FROM metrics_samples`).Scan(&ts); err != nil {
		return 0, fmt.Errorf("latest sample: %w", err)
	}
	return ts.Int64, nil
}

// RollupWindow aggregates raw samples in [from,to) into hourly rows, upserting.
// Returns the number of hourly rows written. Samples are kept (prune handles retention).
func (s *Store) RollupWindow(from, to int64) (int, error) {
	if to <= from {
		return 0, nil
	}
	res, err := s.db.Exec(`INSERT INTO metrics_hourly
		(hour_ts, sample_count, avg_cpu, max_cpu, avg_mem, max_mem, avg_disk, avg_swap, avg_load1, net_rx_total, net_tx_total, updated_at)
		SELECT (ts/3600)*3600,
			COUNT(*), AVG(cpu_percent), MAX(cpu_percent), AVG(mem_percent), MAX(mem_percent),
			AVG(disk_percent), AVG(swap_percent), AVG(load_1m), SUM(net_rx_bps*1.0), SUM(net_tx_bps*1.0), ?
		FROM metrics_samples
		WHERE ts >= ? AND ts < ?
		GROUP BY (ts/3600)
		ON CONFLICT (hour_ts) DO UPDATE SET
			sample_count = excluded.sample_count,
			avg_cpu = excluded.avg_cpu, max_cpu = excluded.max_cpu,
			avg_mem = excluded.avg_mem, max_mem = excluded.max_mem,
			avg_disk = excluded.avg_disk, avg_swap = excluded.avg_swap,
			avg_load1 = excluded.avg_load1,
			net_rx_total = excluded.net_rx_total, net_tx_total = excluded.net_tx_total,
			updated_at = excluded.updated_at`,
		time.Now().Unix(), from, to)
	if err != nil {
		return 0, fmt.Errorf("rollup window: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rollup rows affected: %w", err)
	}
	return int(n), nil
}

// QueryHourly returns hourly rows in [from,to] ascending.
func (s *Store) QueryHourly(from, to int64) ([]HourRow, error) {
	rows, err := s.db.Query(`SELECT hour_ts, sample_count, avg_cpu, max_cpu, avg_mem, max_mem,
		avg_disk, avg_swap, avg_load1, net_rx_total, net_tx_total
		FROM metrics_hourly WHERE hour_ts >= ? AND hour_ts <= ? ORDER BY hour_ts ASC`, from, to)
	if err != nil {
		return nil, fmt.Errorf("query hourly: %w", err)
	}
	defer rows.Close()
	var out []HourRow
	for rows.Next() {
		var h HourRow
		if err := rows.Scan(&h.HourTs, &h.SampleCount, &h.AvgCPU, &h.MaxCPU, &h.AvgMem, &h.MaxMem,
			&h.AvgDisk, &h.AvgSwap, &h.AvgLoad1, &h.NetRxTotal, &h.NetTxTotal); err != nil {
			return nil, fmt.Errorf("scan hourly: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Prune deletes raw samples older than samplesBefore and hourly rows older
// than hourlyBefore (both unix seconds). Returns (deleted samples, deleted hours).
func (s *Store) Prune(samplesBefore, hourlyBefore int64) (int64, int64, error) {
	r1, err := s.db.Exec(`DELETE FROM metrics_samples WHERE ts < ?`, samplesBefore)
	if err != nil {
		return 0, 0, fmt.Errorf("prune samples: %w", err)
	}
	r2, err := s.db.Exec(`DELETE FROM metrics_hourly WHERE hour_ts < ?`, hourlyBefore)
	if err != nil {
		return 0, 0, fmt.Errorf("prune hourly: %w", err)
	}
	n1, _ := r1.RowsAffected()
	n2, _ := r2.RowsAffected()
	return n1, n2, nil
}
