package actions

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestFsDownloadReturnsBase64Content(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "edit.txt")
	got, err := FsDownload(context.Background(), map[string]any{"path": target})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	b64, _ := got["content_b64"].(string)
	if b64 == "" {
		t.Fatal("no content_b64")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(decoded) != "original line\n" {
		t.Fatalf("decoded = %q err %v", string(decoded), err)
	}
	if size, _ := got["size"].(int); size != len("original line\n") {
		t.Fatalf("size = %v", got["size"])
	}
}

func TestFsDownloadBinaryFlag(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "bin.bin")
	if err := os.WriteFile(target, []byte{0, 1, 2, 3, 4}, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := FsDownload(context.Background(), map[string]any{"path": target})
	if err != nil {
		t.Fatalf("download binary: %v", err)
	}
	if binary, _ := got["binary"].(bool); !binary {
		t.Fatalf("binary flag = false, want true")
	}
}

func TestFsDownloadRefusesDirAndMissing(t *testing.T) {
	dir := fsWriteFixture(t)
	if _, err := FsDownload(context.Background(), map[string]any{"path": dir}); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := FsDownload(context.Background(), map[string]any{"path": filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("missing file accepted")
	}
}
