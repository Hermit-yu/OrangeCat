// Package main — P7 backup of the metrics SQLite database.
//
// The metrics DB is the panel's own history store (/var/lib/ocp/metrics.db).
// Backup uses the sqlite3 CLI `.backup` (WAL-safe online backup) and verifies
// with `PRAGMA integrity_check`. Restore is a write path behind the three-way
// gate: it snapshots the live DB first, swaps in the chosen backup, verifies,
// and rolls back on any failure. A restore never runs without a preceding
// preview/list of available backups.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

const (
	metricsDBPath      = "/var/lib/ocp/metrics.db"
	backupDirPath      = "/var/lib/ocp/backups"
	sqlite3Bin         = "sqlite3"
	backupNamePattern  = "metrics-20060102T150405Z.db"
	backupMaxKeep      = 20
	backupMaxTotalBytes = 256 << 20
)

// backupInfo describes one on-disk backup file.
type backupInfo struct {
	File string `json:"file"`
	Size int64  `json:"size"`
	Time string `json:"time"`
}

// listBackups scans the backup dir for metrics-*.db files, newest first.
func listBackups() []backupInfo {
	entries, err := os.ReadDir(backupDirPath)
	if err != nil {
		return []backupInfo{}
	}
	var out []backupInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "metrics-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupInfo{
			File: e.Name(),
			Size: info.Size(),
			Time: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File > out[j].File })
	return out
}

// handleBackupCreate runs an online backup + integrity check. Write gate +
// audit (it writes a file to disk).
func (p *panel) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	if err := os.MkdirAll(backupDirPath, 0700); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "备份目录不可用")
		return
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(backupDirPath, "metrics-"+ts+".db")
	// Online backup: sqlite3 .backup (WAL-safe, no lock on live DB).
	if err := sqliteBackup(metricsDBPath, dest); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "备份失败: "+err.Error())
		return
	}
	// Verify integrity of the backup; a corrupt backup is deleted (fail-closed).
	if !integrityOK(dest) {
		_ = os.Remove(dest)
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "备份校验失败（已删除）")
		return
	}
	// Enforce retention: drop oldest beyond max count / total bytes.
	pruneBackups()
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "backup": backupInfo{File: filepath.Base(dest), Size: fileSize(dest), Time: time.Now().UTC().Format(time.RFC3339)}})
}

// handleBackupList lists available backups (read-only).
func (p *panel) handleBackupList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "backups": listBackups()})
}

// handleBackupRestore restores a chosen backup, with live-DB snapshot and
// rollback on failure. Write gate + audit.
func (p *panel) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := p.requireWriteAccess(w, r, authaudit.TypeSystemAction); !ok {
		return
	}
	var in struct {
		File string `json:"file"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "请求格式无效")
		return
	}
	in.File = filepath.Base(strings.TrimSpace(in.File))
	if in.File == "" || !strings.HasPrefix(in.File, "metrics-") || !strings.HasSuffix(in.File, ".db") {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemRequestBad, "备份文件名无效")
		return
	}
	src := filepath.Join(backupDirPath, in.File)
	if _, err := os.Stat(src); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "备份不存在")
		return
	}
	if !integrityOK(src) {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "备份校验失败（拒绝恢复损坏归档）")
		return
	}
	// Snapshot the live DB for rollback.
	ts := time.Now().UTC().Format("20060102T150405Z")
	snap := filepath.Join(backupDirPath, "metrics-pre-restore-"+ts+".db")
	if err := sqliteBackup(metricsDBPath, snap); err != nil {
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "恢复前快照失败: "+err.Error())
		return
	}
	// Swap: restore the chosen backup over the live DB. Use sqlite3 .restore
	// (safe; no need to stop the sampler) then verify.
	if err := sqliteRestore(src, metricsDBPath); err != nil {
		// Roll back to the snapshot.
		_ = sqliteRestore(snap, metricsDBPath)
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "恢复失败（已回滚）: "+err.Error())
		return
	}
	if !integrityOK(metricsDBPath) {
		_ = sqliteRestore(snap, metricsDBPath)
		p.recordSystemRejected(w, r, authaudit.ReasonSystemActionFailed, "恢复后校验失败（已回滚到快照）")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeSystemAction, authaudit.OutcomeSuccess, authaudit.ReasonSystemActionSent); err != nil {
		http.Error(w, "审计写入失败", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "restored": in.File, "snapshot": filepath.Base(snap)})
}

// sqliteBackup runs an online .backup; dst must not exist (we create it).
func sqliteBackup(src, dst string) error {
	_ = os.Remove(dst)
	cmd := exec.Command(sqlite3Bin, src, ".backup '"+dst+"'")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// sqliteRestore restores a backup over the live DB via .restore (safe online).
func sqliteRestore(src, dst string) error {
	cmd := exec.Command(sqlite3Bin, dst, ".restore '"+src+"'")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// integrityOK runs PRAGMA integrity_check and expects "ok".
func integrityOK(path string) bool {
	out, err := exec.Command(sqlite3Bin, path, "PRAGMA integrity_check;").Output()
	return err == nil && strings.TrimSpace(string(out)) == "ok"
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// pruneBackups keeps at most backupMaxKeep newest backups and drops the rest,
// also enforcing a total byte ceiling.
func pruneBackups() {
	all := listBackups()
	var total int64
	for _, b := range all {
		total += b.Size
	}
	// Remove oldest while over count or over bytes.
	for i := len(all) - 1; i >= 0; i-- {
		if len(all)-i > backupMaxKeep || total > backupMaxTotalBytes {
			_ = os.Remove(filepath.Join(backupDirPath, all[i].File))
			total -= all[i].Size
		}
	}
}
