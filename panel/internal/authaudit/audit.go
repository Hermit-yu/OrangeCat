package authaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	TypeLogin           = "login"
	TypeLogout          = "logout"
	TypeProcessKill     = "process_kill"
	TypeContainerAction = "container_action"
	TypeNginxAction     = "nginx_action"
	TypeFsWrite         = "fs_write"
	TypeFsMutate        = "fs_mutate"

	OutcomeSuccess  = "success"
	OutcomeRejected = "rejected"

	ReasonInvalidJSON           = "invalid_json"
	ReasonRequestTooLarge       = "request_too_large"
	ReasonCredentialsMissing    = "credentials_missing"
	ReasonRateLimited           = "rate_limited"
	ReasonBadCredentials        = "bad_credentials"
	ReasonCredentialsAccepted   = "credentials_accepted"
	ReasonOriginMismatch        = "origin_mismatch"
	ReasonSessionMissing        = "session_missing"
	ReasonSessionExpiredUnknown = "session_expired_or_unknown"
	ReasonCSRFFailed            = "csrf_failed"
	ReasonLogoutCompleted       = "logout_completed"
	ReasonKillSignalSent        = "kill_signal_sent"
	ReasonKillRejected          = "kill_rejected"
	ReasonKillRequestInvalid    = "kill_request_invalid"
	ReasonKillPIDInitForbidden  = "kill_pid_init_forbidden"
	ReasonContainerActionSent   = "container_action_sent"
	ReasonContainerActionFailed = "container_action_failed"
	ReasonContainerRequestBad   = "container_request_invalid"
	ReasonNginxActionSent       = "nginx_action_sent"
	ReasonNginxActionFailed     = "nginx_action_failed"
	ReasonNginxRequestBad       = "nginx_request_invalid"
	ReasonFsWriteSent           = "fs_write_sent"
	ReasonFsWriteFailed         = "fs_write_failed"
	ReasonFsWriteRequestBad     = "fs_write_request_invalid"
	ReasonFsRollbackSent        = "fs_rollback_sent"
	ReasonFsRollbackFailed      = "fs_rollback_failed"
	ReasonFsRollbackRequestBad  = "fs_rollback_request_invalid"
	ReasonFsRenameSent          = "fs_rename_sent"
	ReasonFsRenameFailed        = "fs_rename_failed"
	ReasonFsRenameRequestBad    = "fs_rename_request_invalid"
	ReasonFsRemoveSent          = "fs_remove_sent"
	ReasonFsRemoveFailed        = "fs_remove_failed"
	ReasonFsRemoveRequestBad    = "fs_remove_request_invalid"
	ReasonFsRestoreSent         = "fs_restore_sent"
	ReasonFsRestoreFailed       = "fs_restore_failed"
	ReasonFsRestoreRequestBad   = "fs_restore_request_invalid"
)

var allowedReasons = map[string]struct{}{
	ReasonInvalidJSON: {}, ReasonRequestTooLarge: {}, ReasonCredentialsMissing: {},
	ReasonRateLimited: {}, ReasonBadCredentials: {}, ReasonCredentialsAccepted: {},
	ReasonOriginMismatch: {}, ReasonSessionMissing: {}, ReasonSessionExpiredUnknown: {},
	ReasonCSRFFailed: {}, ReasonLogoutCompleted: {},
	ReasonKillSignalSent: {}, ReasonKillRejected: {}, ReasonKillRequestInvalid: {},
	ReasonKillPIDInitForbidden: {},
	ReasonContainerActionSent:  {}, ReasonContainerActionFailed: {}, ReasonContainerRequestBad: {},
	ReasonNginxActionSent: {}, ReasonNginxActionFailed: {}, ReasonNginxRequestBad: {},
	ReasonFsWriteSent: {}, ReasonFsWriteFailed: {}, ReasonFsWriteRequestBad: {},
	ReasonFsRollbackSent: {}, ReasonFsRollbackFailed: {}, ReasonFsRollbackRequestBad: {},
	ReasonFsRenameSent: {}, ReasonFsRenameFailed: {}, ReasonFsRenameRequestBad: {},
	ReasonFsRemoveSent: {}, ReasonFsRemoveFailed: {}, ReasonFsRemoveRequestBad: {},
	ReasonFsRestoreSent: {}, ReasonFsRestoreFailed: {}, ReasonFsRestoreRequestBad: {},
}

// Event deliberately has no username, password, cookie, token, URL, or body fields.
type Event struct {
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason,omitempty"`
	ClientIP string    `json:"client_ip,omitempty"`
	Method   string    `json:"method,omitempty"`
}

type Writer struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	closed   bool
}

// New creates a private JSONL log with one bounded rotated copy at path+".1".
func New(path string, maxBytes int64) (*Writer, error) {
	if strings.TrimSpace(path) == "" || maxBytes <= 0 {
		return nil, errors.New("audit path and positive size limit are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	for _, candidate := range []string{path, path + ".1"} {
		if err := validateExistingLog(candidate, maxBytes); err != nil {
			return nil, err
		}
	}
	f, err := openLog(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Writer{path: path, maxBytes: maxBytes, file: f}, nil
}

func validateExistingLog(path string, maxBytes int64) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect auth audit file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("auth audit path is not a regular file: %s", path)
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("existing auth audit file exceeds configured size limit: %s", path)
	}
	return nil
}

func openLog(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("audit target is not a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (w *Writer) Record(event Event) error {
	if event.Type != TypeLogin && event.Type != TypeLogout && event.Type != TypeProcessKill && event.Type != TypeContainerAction && event.Type != TypeNginxAction && event.Type != TypeFsWrite && event.Type != TypeFsMutate {
		return fmt.Errorf("invalid auth event type %q", event.Type)
	}
	if event.Outcome != OutcomeSuccess && event.Outcome != OutcomeRejected {
		return fmt.Errorf("invalid auth event outcome %q", event.Outcome)
	}
	if _, ok := allowedReasons[event.Reason]; !ok {
		return fmt.Errorf("auth audit reason is not a fixed classification")
	}
	if len(event.Type) > 16 || len(event.Outcome) > 16 || len(event.Reason) > 64 || len(event.ClientIP) > 64 || len(event.Method) > 16 {
		return errors.New("auth audit field exceeds its limit")
	}
	if event.ClientIP != "" {
		if _, err := netip.ParseAddr(event.ClientIP); err != nil {
			return errors.New("auth audit client address is not an IP")
		}
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	} else {
		event.At = event.At.UTC()
	}
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode auth audit event: %w", err)
	}
	line = append(line, '\n')
	if int64(len(line)) > w.maxBytes {
		return errors.New("auth audit event exceeds file size limit")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.file == nil {
		return errors.New("auth audit writer is closed")
	}
	info, err := w.file.Stat()
	if err != nil {
		return fmt.Errorf("stat auth audit log: %w", err)
	}
	if info.Size()+int64(len(line)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := w.file.Write(line)
	if err != nil {
		return fmt.Errorf("write auth audit event: %w", err)
	}
	if n != len(line) {
		return errors.New("short write to auth audit log")
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync auth audit log: %w", err)
	}
	return nil
}

func (w *Writer) rotateLocked() error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync before auth audit rotation: %w", err)
	}
	if err := w.file.Close(); err != nil {
		w.file = nil
		return fmt.Errorf("close auth audit log for rotation: %w", err)
	}
	w.file = nil
	backup := w.path + ".1"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		w.reopenLocked()
		return fmt.Errorf("remove prior auth audit rotation: %w", err)
	}
	if err := os.Rename(w.path, backup); err != nil {
		w.reopenLocked()
		return fmt.Errorf("rotate auth audit log: %w", err)
	}
	f, err := openLog(w.path)
	if err != nil {
		_ = os.Rename(backup, w.path)
		w.reopenLocked()
		return fmt.Errorf("create new auth audit log: %w", err)
	}
	w.file = f
	return nil
}

func (w *Writer) reopenLocked() {
	f, err := openLog(w.path)
	if err == nil {
		w.file = f
	}
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		w.file = nil
		return err
	}
	err := w.file.Close()
	w.file = nil
	return err
}
