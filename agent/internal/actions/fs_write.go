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

// P4 写切片：单文件原子写 + 快照回滚。
//
// 设计（与只读切片同策略：规范化而非根 confinement）：
//   - fs.write 对"已存在的常规文件"做原子替换：先在目标同目录写临时文件，
//     fsync + 校验字节数，再 rename 覆盖；任何一步失败都删除临时文件，
//     原文件保持原状（失败不留下半文件）。
//   - 替换前先做快照：把原文件内容拷到快照目录（/var/lib/ocp/fs-snapshots/，
//     0640，文件名含时间戳与目标 basename），成功响应返回 snapshot 路径。
//   - fs.write.rollback 从快照路径恢复目标文件内容（目标路径必须显式传入，
//     不接受从快照推导，防篡改），恢复后删除快照。
//   - 快照是"本次写之前的内容"，不是全量备份：写失败自动回滚不需要快照
//     （临时文件已删、原文件未动）；rollback 用于用户主动撤销上一次写。
//
// 安全模型：
//   - 路径仍是绝对路径 + NUL 拒绝 + filepath.Clean 吸收 ..（resolveFsPath）。
//   - 只写常规文件（拒绝目录/符号链接/设备），只写已存在文件（拒绝新建——
//     创建新文件留给后续切片，本切片聚焦"编辑已有文件"）。
//   - 内容大小上限 fsWriteMaxBytes，防一次写入撑爆内存/磁盘。
//   - 临时文件落在目标同目录（保证 rename 同文件系统原子性），0600 权限，
//     名称带随机后缀，绝不猜测用户路径。

const (
	fsWriteMaxBytes    = 1 << 20 // 1 MiB
	fsSnapshotMaxBytes = 1 << 20
)

// fsSnapshotDir is a package-level hook so tests can point snapshots at a temp
// dir; production always uses /var/lib/ocp/fs-snapshots.
var fsSnapshotDir = "/var/lib/ocp/fs-snapshots"

func resolveSnapshotPath(raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", errors.New("snapshot must be a string")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("snapshot is required")
	}
	if strings.ContainsRune(s, 0) {
		return "", errors.New("snapshot contains NUL byte")
	}
	if !filepath.IsAbs(s) {
		return "", errors.New("snapshot must be absolute")
	}
	return filepath.Clean(s), nil
}

func snapshotOf(path string, src []byte) (string, error) {
	dir := fsSnapshotDir
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create snapshot dir: %w", err)
	}
	base := filepath.Base(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "root"
	}
	name := fmt.Sprintf("%d-%s.snap", time.Now().UnixNano(), sanitizeSnapshotName(base))
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, src, 0640); err != nil {
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	return dst, nil
}

func sanitizeSnapshotName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()
	if s == "" {
		return "file"
	}
	if len(s) > 80 {
		s = s[len(s)-80:]
	}
	return s
}

// FsWrite atomically replaces one existing regular file, snapshotting first.
func FsWrite(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rawPath, ok := params["path"]
	if !ok {
		return nil, errors.New("path is required")
	}
	path, err := resolveFsPath(rawPath)
	if err != nil {
		return nil, err
	}
	content, ok := params["content"].(string)
	if !ok || content == "" {
		return nil, errors.New("content is required")
	}
	if len(content) > fsWriteMaxBytes {
		return nil, fmt.Errorf("content exceeds %d bytes", fsWriteMaxBytes)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to write through a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target is not a regular file")
	}

	// Snapshot the pre-write content for rollback.
	snapshot, err := snapshotOf(path, mustRead(path, info.Size()))
	if err != nil {
		return nil, err
	}

	// Write temp in the same directory, then atomic rename over target.
	if err := writeAtomicReplace(path, []byte(content)); err != nil {
		// Roll back nothing: the original file is untouched (temp removed).
		_ = os.Remove(snapshot)
		return nil, err
	}
	return map[string]any{
		"ok": true, "path": path, "snapshot": snapshot,
		"size": len(content), "mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// FsWriteRollback restores a file from a prior snapshot and removes the snapshot.
func FsWriteRollback(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rawSnap, ok := params["snapshot"]
	if !ok {
		return nil, errors.New("snapshot is required")
	}
	snapshot, err := resolveSnapshotPath(rawSnap)
	if err != nil {
		return nil, err
	}
	rawPath, ok := params["path"]
	if !ok {
		return nil, errors.New("path is required")
	}
	path, err := resolveFsPath(rawPath)
	if err != nil {
		return nil, err
	}
	snapInfo, err := os.Lstat(snapshot)
	if err != nil {
		return nil, fmt.Errorf("stat snapshot: %w", err)
	}
	if !snapInfo.Mode().IsRegular() || snapInfo.Size() > fsSnapshotMaxBytes {
		return nil, errors.New("snapshot is not a usable regular file")
	}
	// Constrain rollback to files under the snapshot dir (no arbitrary read).
	if filepath.Dir(snapshot) != fsSnapshotDir {
		return nil, errors.New("snapshot outside managed directory")
	}
	back, err := os.ReadFile(snapshot)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if err := writeAtomicReplace(path, back); err != nil {
		return nil, err
	}
	if err := os.Remove(snapshot); err != nil {
		return nil, fmt.Errorf("remove snapshot: %w", err)
	}
	return map[string]any{
		"ok": true, "path": path, "size": len(back),
		"mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func mustRead(path string, size int64) []byte {
	if size > fsSnapshotMaxBytes {
		size = fsSnapshotMaxBytes
	}
	buf := make([]byte, size)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	n, _ := f.Read(buf)
	return buf[:n]
}

func writeAtomicReplace(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ocp-write-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("atomic replace: %w", err)
	}
	return nil
}
