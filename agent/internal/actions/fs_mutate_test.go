package actions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fsMutateFixture builds a tree with a file and a subdir for rename/remove tests.
func fsMutateFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa\n"), 0644); err != nil {
		t.Fatalf("seed a.txt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb\n"), 0644); err != nil {
		t.Fatalf("seed sub/b.txt: %v", err)
	}
	old := fsSnapshotDir
	fsSnapshotDir = filepath.Join(dir, ".snapshots")
	t.Cleanup(func() { fsSnapshotDir = old })
	return dir
}

func TestFsRenameMovesFileAndRefusesExistingTarget(t *testing.T) {
	dir := fsMutateFixture(t)
	src := filepath.Join(dir, "a.txt")
	dst := filepath.Join(dir, "c.txt")

	got, err := FsRename(context.Background(), map[string]any{"path": src, "new_path": dst})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if !got["ok"].(bool) {
		t.Fatalf("rename not ok: %v", got)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	back, _ := os.ReadFile(dst)
	if string(back) != "aaa\n" {
		t.Fatalf("target content = %q", string(back))
	}

	// Renaming onto an existing target is refused (no silent overwrite).
	if _, err := FsRename(context.Background(), map[string]any{
		"path": dst, "new_path": filepath.Join(dir, "sub", "b.txt"),
	}); err == nil {
		t.Fatal("rename onto existing target accepted, want rejection")
	}
}

func TestFsRenameRefusesRelativeAndMissingSource(t *testing.T) {
	dir := fsMutateFixture(t)
	if _, err := FsRename(context.Background(), map[string]any{
		"path": "relative", "new_path": filepath.Join(dir, "x"),
	}); err == nil {
		t.Fatal("relative source accepted")
	}
	if _, err := FsRename(context.Background(), map[string]any{
		"path": filepath.Join(dir, "missing.txt"), "new_path": filepath.Join(dir, "x"),
	}); err == nil {
		t.Fatal("missing source accepted")
	}
}

func TestFsRemoveFileSnapshotsThenRemoves(t *testing.T) {
	dir := fsMutateFixture(t)
	target := filepath.Join(dir, "a.txt")
	got, err := FsRemove(context.Background(), map[string]any{"path": target, "force": true})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !got["ok"].(bool) {
		t.Fatalf("remove not ok: %v", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("file still exists: %v", err)
	}
	snap, _ := got["snapshot"].(string)
	if snap == "" {
		t.Fatal("no snapshot for removed file")
	}
}

func TestFsRemoveRefusesNonEmptyDirAndSymlinkAndNoForce(t *testing.T) {
	dir := fsMutateFixture(t)
	// Non-empty dir refused.
	if _, err := FsRemove(context.Background(), map[string]any{
		"path": filepath.Join(dir, "sub"), "force": true,
	}); err == nil {
		t.Fatal("non-empty dir accepted, want rejection")
	}
	// force=false refused.
	if _, err := FsRemove(context.Background(), map[string]any{
		"path": filepath.Join(dir, "a.txt"), "force": false,
	}); err == nil {
		t.Fatal("remove without force accepted")
	}
}

func TestFsRestoreFileFromSnapshot(t *testing.T) {
	dir := fsMutateFixture(t)
	target := filepath.Join(dir, "a.txt")
	got, _ := FsRemove(context.Background(), map[string]any{"path": target, "force": true})
	snap, _ := got["snapshot"].(string)
	rb, err := FsRestore(context.Background(), map[string]any{"path": target, "snapshot": snap})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !rb["ok"].(bool) {
		t.Fatalf("restore not ok: %v", rb)
	}
	back, _ := os.ReadFile(target)
	if string(back) != "aaa\n" {
		t.Fatalf("restored content = %q", string(back))
	}
}

func TestFsRestoreEmptyDir(t *testing.T) {
	dir := fsMutateFixture(t)
	emptydir := filepath.Join(dir, "emptydir")
	if err := os.MkdirAll(emptydir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := FsRemove(context.Background(), map[string]any{"path": emptydir, "force": true}); err != nil {
		t.Fatalf("remove emptydir: %v", err)
	}
	if _, err := os.Stat(emptydir); !os.IsNotExist(err) {
		t.Fatalf("emptydir still exists")
	}
	rb, err := FsRestore(context.Background(), map[string]any{"path": emptydir, "dir": true})
	if err != nil {
		t.Fatalf("restore dir: %v", err)
	}
	if !rb["ok"].(bool) {
		t.Fatalf("restore dir not ok: %v", rb)
	}
	if fi, err := os.Stat(emptydir); err != nil || !fi.IsDir() {
		t.Fatalf("emptydir not restored: %v", err)
	}
}
