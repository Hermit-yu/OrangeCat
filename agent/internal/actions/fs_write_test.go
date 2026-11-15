package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fsWriteFixture builds a tree with one editable file for write tests.
func fsWriteFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "edit.txt"), []byte("original line\n"), 0644); err != nil {
		t.Fatalf("seed edit.txt: %v", err)
	}
	// Point snapshots at a subdir of the temp tree so tests never touch /var/lib.
	old := fsSnapshotDir
	fsSnapshotDir = filepath.Join(dir, ".snapshots")
	t.Cleanup(func() { fsSnapshotDir = old })
	return dir
}

func TestFsWriteCreatesSnapshotAndReplacesAtomically(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "edit.txt")

	got, err := FsWrite(context.Background(), map[string]any{
		"path":    target,
		"content": "new line one\nnew line two\n",
	})
	if err != nil {
		t.Fatalf("FsWrite error: %v", err)
	}
	if !got["ok"].(bool) {
		t.Fatalf("write reported not ok: %v", got)
	}
	snapshot, _ := got["snapshot"].(string)
	if snapshot == "" {
		t.Fatalf("no snapshot path returned")
	}
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	back, err := os.ReadFile(snapshot)
	if err != nil || string(back) != "original line\n" {
		t.Fatalf("snapshot content = %q, err %v", string(back), err)
	}
	final, err := os.ReadFile(target)
	if err != nil || string(final) != "new line one\nnew line two\n" {
		t.Fatalf("final content = %q, err %v", string(final), err)
	}
}

func TestFsWriteRejectsNonAbsoluteAndEmpty(t *testing.T) {
	dir := fsWriteFixture(t)
	if _, err := FsWrite(context.Background(), map[string]any{
		"path": "relative.txt", "content": "x",
	}); err == nil {
		t.Fatal("relative path accepted, want rejection")
	}
	if _, err := FsWrite(context.Background(), map[string]any{
		"path": filepath.Join(dir, "edit.txt"), "content": "",
	}); err == nil {
		t.Fatal("empty content accepted, want rejection")
	}
}

func TestFsWriteRejectsMissingTarget(t *testing.T) {
	dir := fsWriteFixture(t)
	if _, err := FsWrite(context.Background(), map[string]any{
		"path": filepath.Join(dir, "does-not-exist.txt"), "content": "x",
	}); err == nil {
		t.Fatal("missing target accepted, want rejection")
	}
}

func TestFsWriteRollbackRestoresSnapshot(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "edit.txt")
	got, err := FsWrite(context.Background(), map[string]any{
		"path": target, "content": "modified\n",
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	snapshot, _ := got["snapshot"].(string)
	if snapshot == "" {
		t.Fatal("no snapshot")
	}
	rb, err := FsWriteRollback(context.Background(), map[string]any{"snapshot": snapshot, "path": target})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !rb["ok"].(bool) {
		t.Fatalf("rollback not ok: %v", rb)
	}
	final, _ := os.ReadFile(target)
	if string(final) != "original line\n" {
		t.Fatalf("after rollback = %q, want original", string(final))
	}
}

func TestFsWriteRollbackRefusesMissingSnapshot(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "edit.txt")
	if _, err := FsWriteRollback(context.Background(), map[string]any{
		"snapshot": filepath.Join(dir, "nope.snap"), "path": target,
	}); err == nil {
		t.Fatal("missing snapshot accepted, want rejection")
	}
	if strings.TrimSpace(target) == "" {
		t.Fatal("sanity")
	}
}
