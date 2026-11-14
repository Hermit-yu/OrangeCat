package authaudit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterRotatesWithinConfiguredBoundAndUsesPrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	const maxBytes = 512
	writer, err := New(path, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		err := writer.Record(Event{
			At:       time.Date(2026, 11, 14, 10, 0, i, 0, time.UTC),
			Type:     "login",
			Outcome:  "rejected",
			Reason:   "bad_credentials",
			ClientIP: "192.0.2.10",
			Method:   "POST",
		})
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{path, path + ".1"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Size() > maxBytes {
			t.Errorf("%s has %d bytes, exceeds %d", name, info.Size(), maxBytes)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Fatalf("unexpected second rotated file: err=%v", err)
	}

	for _, name := range []string{path, path + ".1"} {
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var fields map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil {
				_ = f.Close()
				t.Fatalf("invalid JSONL record in %s: %v", name, err)
			}
			for key := range fields {
				if key != "at" && key != "type" && key != "outcome" && key != "reason" && key != "client_ip" && key != "method" {
					_ = f.Close()
					t.Errorf("unexpected audit field %q", key)
				}
			}
			encoded, _ := json.Marshal(fields)
			for _, forbidden := range []string{"password", "username", "session", "csrf", "token", "request_body"} {
				if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
					_ = f.Close()
					t.Errorf("audit record contains forbidden field/value marker %q", forbidden)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
	}
}

func TestNewRejectsSymlinkLogPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "auth-audit.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	writer, err := New(path, 512)
	if writer != nil {
		_ = writer.Close()
	}
	if err == nil {
		t.Fatal("New accepted a symlink as the audit log")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestWriterRejectsEventLargerThanRotationLimit(t *testing.T) {
	writer, err := New(filepath.Join(t.TempDir(), "auth-audit.jsonl"), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Record(Event{Type: "login", Outcome: "rejected", Reason: ReasonBadCredentials}); err == nil {
		t.Fatal("Record accepted an event larger than the configured file bound")
	}
}

func TestWriterRejectsOversizedPreexistingCurrentOrRotatedFile(t *testing.T) {
	for _, suffix := range []string{"", ".1"} {
		t.Run("suffix="+suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
			if err := os.WriteFile(path+suffix, []byte(strings.Repeat("x", 513)), 0600); err != nil {
				t.Fatal(err)
			}
			writer, err := New(path, 512)
			if writer != nil {
				_ = writer.Close()
			}
			if err == nil {
				t.Fatal("New accepted a preexisting file larger than the configured cap")
			}
		})
	}
}

func TestNewRejectsSymlinkRotatedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth-audit.jsonl")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".1"); err != nil {
		t.Fatal(err)
	}
	if writer, err := New(path, 512); err == nil {
		_ = writer.Close()
		t.Fatal("New accepted a symlinked rotated log")
	}
}

func TestWriterRejectsUnclassifiedReason(t *testing.T) {
	writer, err := New(filepath.Join(t.TempDir(), "auth-audit.jsonl"), 512)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Record(Event{Type: TypeLogin, Outcome: OutcomeRejected, Reason: "password was hunter2"}); err == nil {
		t.Fatal("Record accepted a reason outside the fixed classification set")
	}
}
