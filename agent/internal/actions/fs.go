package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// P4 slice 1: read-only file browsing (list / read / stat).
//
// The panel is planned as a root-scoped file manager ("允许根目录管理"), so the
// path policy here is normalization, not confinement: the path must be an
// absolute, NUL-free string; `..` segments are absorbed by filepath.Clean.
// Symlinks are reported as such by list/stat; read opens the file the OS
// resolves. Write operations (with snapshot/atomic replace/rollback) are a
// later slice and are deliberately absent here.
//
// Bounds (defense against huge dirs / huge files / binary blobs):
//   - list caps at fsListMaxEntries with a truncated marker;
//   - read caps content at fsReadMaxBytes with a truncated marker;
//   - read scans the first fsNULScanBytes for a NUL byte and refuses to
//     return binary content at all (binary=true, no content).

const (
	fsListMaxEntries = 1000
	fsReadMaxBytes   = 256 << 10
	fsNULScanBytes   = 8 << 10
)

// resolveFsPath validates and cleans one user-supplied path.
func resolveFsPath(p any) (string, error) {
	s, ok := p.(string)
	if !ok {
		return "", errors.New("path must be a string")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("path is required")
	}
	if strings.ContainsRune(s, 0) {
		return "", errors.New("path contains NUL byte")
	}
	if !filepath.IsAbs(s) {
		return "", errors.New("path must be absolute")
	}
	return filepath.Clean(s), nil
}

func fsTypeFromMode(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	case m.IsRegular():
		return "file"
	default:
		return "other"
	}
}

// FsList returns one row per directory entry: name, type, size, mode, mtime.
func FsList(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	raw, ok := params["path"]
	if !ok {
		return nil, errors.New("path is required")
	}
	path, err := resolveFsPath(raw)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	names, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}
	entries := make([]map[string]any, 0, len(names))
	truncated := false
	for _, de := range names {
		if len(entries) >= fsListMaxEntries {
			truncated = true
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		entries = append(entries, map[string]any{
			"name":    de.Name(),
			"type":    fsTypeFromMode(fi.Mode()),
			"size":    fi.Size(),
			"mode":    fi.Mode().String(),
			"mtime":   fi.ModTime().Unix(),
			"mtime_r": fi.ModTime().UTC().Format(time.RFC3339),
		})
	}
	return map[string]any{
		"path":      path,
		"entries":   entries,
		"count":     len(entries),
		"truncated": truncated,
	}, nil
}

// FsRead returns bounded file content as text, or a binary flag instead.
func FsRead(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	raw, ok := params["path"]
	if !ok {
		return nil, errors.New("path is required")
	}
	path, err := resolveFsPath(raw)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	head := make([]byte, fsNULScanBytes)
	n, _ := f.Read(head)
	if n > 0 {
		for _, b := range head[:n] {
			if b == 0 {
				return map[string]any{
					"path": path, "binary": true, "size": info.Size(),
					"mode": info.Mode().String(), "mtime": info.ModTime().Unix(),
				}, nil
			}
		}
	}
	_, _ = f.Seek(0, 0)
	limit := fsReadMaxBytes
	if info.Size() >= 0 && info.Size() < int64(limit) {
		limit = int(info.Size())
	}
	buf := make([]byte, limit)
	read, err := f.Read(buf)
	if err != nil && read == 0 {
		return nil, fmt.Errorf("read file: %w", err)
	}
	truncated := info.Size() > int64(read)
	return map[string]any{
		"path": path, "content": string(buf[:read]), "size": info.Size(),
		"mode": info.Mode().String(), "mtime": info.ModTime().Unix(),
		"binary": false, "truncated": truncated,
	}, nil
}

// FsStat reports one path's metadata without following into a new location.
func FsStat(ctx context.Context, params map[string]any) (map[string]any, error) {
	raw, ok := params["path"]
	if !ok {
		return nil, errors.New("path is required")
	}
	path, err := resolveFsPath(raw)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	return map[string]any{
		"path": path, "type": fsTypeFromMode(info.Mode()), "size": info.Size(),
		"mode": info.Mode().String(), "mtime": info.ModTime().Unix(),
		"mtime_r": info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}
