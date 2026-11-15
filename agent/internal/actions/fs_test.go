package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fsFixture builds a small tree in t.TempDir() and returns its root.
func fsFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "nested.txt"), []byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := []byte{'B', 0x00, 'I', 'N'}
	if err := os.WriteFile(filepath.Join(root, "bin.bin"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	big := []byte(strings.Repeat("a\n", 200_000)) // ~400KB, over the read cap
	if err := os.WriteFile(filepath.Join(root, "big.log"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFsListReturnsEntries(t *testing.T) {
	root := fsFixture(t)
	res, err := FsList(context.Background(), map[string]any{"path": root})
	if err != nil {
		t.Fatalf("fs.list: %v", err)
	}
	entries, _ := res["entries"].([]map[string]any)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d (%v)", len(entries), entries)
	}
	byName := map[string]map[string]any{}
	for _, e := range entries {
		byName[e["name"].(string)] = e
	}
	if f := byName["hello.txt"]; f == nil {
		t.Fatal("hello.txt missing")
	} else if f["type"] != "file" {
		t.Fatalf("hello.txt type = %v", f["type"])
	} else if sz, _ := f["size"].(int64); sz != int64(len("hello world\n")) {
		t.Fatalf("hello.txt size = %v", f["size"])
	}
	if d := byName["sub"]; d == nil || d["type"] != "dir" {
		t.Fatalf("sub should be type dir, got %v", d)
	}
	if tr, _ := res["truncated"].(bool); tr {
		t.Fatal("small dir must not be truncated")
	}
}

func TestFsListRejectsRelativePath(t *testing.T) {
	if _, err := FsList(context.Background(), map[string]any{"path": "etc/passwd"}); err == nil {
		t.Fatal("relative path must be rejected")
	}
}

func TestFsListRejectsNULAndEmpty(t *testing.T) {
	for _, p := range []string{"", "  ", "/tmp/\x00bad"} {
		if _, err := FsList(context.Background(), map[string]any{"path": p}); err == nil {
			t.Fatalf("path %q must be rejected", p)
		}
	}
}

func TestFsListMissingPath(t *testing.T) {
	if _, err := FsList(context.Background(), map[string]any{"path": filepath.Join(fsFixture(t), "nope")}); err == nil {
		t.Fatal("missing dir must error")
	}
}

func TestFsListFilePathRejected(t *testing.T) {
	root := fsFixture(t)
	if _, err := FsList(context.Background(), map[string]any{"path": filepath.Join(root, "hello.txt")}); err == nil {
		t.Fatal("a file path must be rejected for list")
	}
}

func TestFsReadTextFile(t *testing.T) {
	root := fsFixture(t)
	res, err := FsRead(context.Background(), map[string]any{"path": filepath.Join(root, "hello.txt")})
	if err != nil {
		t.Fatalf("fs.read: %v", err)
	}
	if b, _ := res["binary"].(bool); b {
		t.Fatal("text file flagged binary")
	}
	if got, _ := res["content"].(string); got != "hello world\n" {
		t.Fatalf("content = %q", got)
	}
	if tr, _ := res["truncated"].(bool); tr {
		t.Fatal("small file must not be truncated")
	}
}

func TestFsReadBinaryRejected(t *testing.T) {
	root := fsFixture(t)
	res, err := FsRead(context.Background(), map[string]any{"path": filepath.Join(root, "bin.bin")})
	if err != nil {
		t.Fatalf("binary read should not hard-error, got %v", err)
	}
	if b, _ := res["binary"].(bool); !b {
		t.Fatal("binary file must be flagged binary")
	}
	if _, ok := res["content"]; ok {
		t.Fatal("binary file must not carry content")
	}
}

func TestFsReadTruncatesLargeFile(t *testing.T) {
	root := fsFixture(t)
	res, err := FsRead(context.Background(), map[string]any{"path": filepath.Join(root, "big.log")})
	if err != nil {
		t.Fatalf("fs.read big: %v", err)
	}
	content, _ := res["content"].(string)
	if len(content) > fsReadMaxBytes {
		t.Fatalf("content %d bytes exceeds cap %d", len(content), fsReadMaxBytes)
	}
	if tr, _ := res["truncated"].(bool); !tr {
		t.Fatal("large file must be marked truncated")
	}
}

func TestFsReadDirectoryRejected(t *testing.T) {
	root := fsFixture(t)
	if _, err := FsRead(context.Background(), map[string]any{"path": filepath.Join(root, "sub")}); err == nil {
		t.Fatal("directory must be rejected for read")
	}
}

func TestFsReadMissing(t *testing.T) {
	root := fsFixture(t)
	if _, err := FsRead(context.Background(), map[string]any{"path": filepath.Join(root, "nope.txt")}); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestFsStatFileAndDir(t *testing.T) {
	root := fsFixture(t)
	res, err := FsStat(context.Background(), map[string]any{"path": filepath.Join(root, "hello.txt")})
	if err != nil {
		t.Fatalf("fs.stat: %v", err)
	}
	if res["type"] != "file" {
		t.Fatalf("type = %v", res["type"])
	}
	if sz, _ := res["size"].(int64); sz != int64(len("hello world\n")) {
		t.Fatalf("size = %v", res["size"])
	}
	res, err = FsStat(context.Background(), map[string]any{"path": filepath.Join(root, "sub")})
	if err != nil {
		t.Fatalf("fs.stat dir: %v", err)
	}
	if res["type"] != "dir" {
		t.Fatalf("dir type = %v", res["type"])
	}
}

func TestFsStatMissing(t *testing.T) {
	root := fsFixture(t)
	if _, err := FsStat(context.Background(), map[string]any{"path": filepath.Join(root, "nope.txt")}); err == nil {
		t.Fatal("missing path must error")
	}
}

// TestFsPathTraversalGetsCleaned verifies that ../ segments are absorbed by the
// cleaner instead of escaping anywhere. The panel is a root-scoped file manager,
// so traversal is not an escape primitive, but the resolved path must still be a
// real absolute location.
func TestFsPathTraversalGetsCleaned(t *testing.T) {
	got, err := resolveFsPath("/tmp/../etc")
	if err != nil {
		t.Fatalf("clean path errored: %v", err)
	}
	if got != "/etc" {
		t.Fatalf("expected /etc, got %q", got)
	}
}
