package actions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFsUploadCreatesNewFileAndOverwritesWithSnapshot(t *testing.T) {
	dir := fsWriteFixture(t)
	target := filepath.Join(dir, "uploaded.txt")

	// New file.
	got, err := FsUpload(context.Background(), map[string]any{
		"path": dir, "name": "uploaded.txt", "content": "hello-upload\n",
	})
	if err != nil {
		t.Fatalf("upload new: %v", err)
	}
	if !got["ok"].(bool) {
		t.Fatalf("upload not ok: %v", got)
	}
	back, _ := os.ReadFile(target)
	if string(back) != "hello-upload\n" {
		t.Fatalf("uploaded content = %q", string(back))
	}

	// Overwrite existing file → snapshot taken.
	got2, err := FsUpload(context.Background(), map[string]any{
		"path": dir, "name": "uploaded.txt", "content": "v2\n",
	})
	if err != nil {
		t.Fatalf("upload overwrite: %v", err)
	}
	snap, _ := got2["snapshot"].(string)
	if snap == "" {
		t.Fatal("no snapshot on overwrite")
	}
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	back2, _ := os.ReadFile(target)
	if string(back2) != "v2\n" {
		t.Fatalf("overwritten content = %q", string(back2))
	}
}

func TestFsUploadRejectsBadTargetAndName(t *testing.T) {
	dir := fsWriteFixture(t)
	// Missing dir.
	if _, err := FsUpload(context.Background(), map[string]any{
		"path": filepath.Join(dir, "nope"), "name": "x.txt", "content": "x",
	}); err == nil {
		t.Fatal("missing dir accepted")
	}
	// Relative name with separators.
	if _, err := FsUpload(context.Background(), map[string]any{
		"path": dir, "name": "../evil.txt", "content": "x",
	}); err == nil {
		t.Fatal("path-traversal name accepted")
	}
	// Empty content.
	if _, err := FsUpload(context.Background(), map[string]any{
		"path": dir, "name": "x.txt", "content": "",
	}); err == nil {
		t.Fatal("empty content accepted")
	}
	// Oversized content.
	big := make([]byte, fsWriteMaxBytes+1)
	if _, err := FsUpload(context.Background(), map[string]any{
		"path": dir, "name": "x.txt", "content": string(big),
	}); err == nil {
		t.Fatal("oversized content accepted")
	}
}
