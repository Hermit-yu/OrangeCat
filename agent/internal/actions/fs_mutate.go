package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// P4-3 写切片：改名 + 删除（带快照恢复）。
//
// 设计（与 P4-1/P4-2 同策略：规范化而非根 confinement）：
//   - fs.rename：把已存在的文件/空目录改名到新路径。目标已存在则拒绝
//     （不静默覆盖）。源与目标都必须是绝对路径，跨文件系统时 os.Rename
//     失败会诚实报错（不做跨设备拷贝，避免复杂化）。
//   - fs.remove：删除一个文件或空目录。删除文件前先快照内容到托管目录
//     （供 fs.restore 恢复）；空目录删除记录 dir=true 标记。force 必须显式
//     true——这是破坏性动作，面板上只有一种心智模型（同 P2 KILL）。
//   - fs.restore：从快照恢复被删文件（重写 + 删快照），或重建被删的空目录
//     （dir=true）。目标路径显式传入，不接受从快照推导。
//
// 边界：只操作常规文件与空目录；拒绝符号链接（防跳出）；拒绝非空目录删除；
// 恢复时若目标已存在则先快照覆盖前内容（安全网），删除快照。

// FsRename moves an existing file or empty directory to a new path.
func FsRename(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	src, err := resolveFsPath(params["path"])
	if err != nil {
		return nil, err
	}
	dst, err := resolveFsPath(params["new_path"])
	if err != nil {
		return nil, err
	}
	if src == dst {
		return nil, errors.New("source and target are the same")
	}
	info, err := os.Lstat(src)
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to rename a symlink")
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, errors.New("source is not a regular file or directory")
	}
	if _, err := os.Lstat(dst); err == nil {
		return nil, errors.New("target already exists")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return nil, fmt.Errorf("rename: %w", err)
	}
	return map[string]any{
		"ok": true, "path": dst, "old_path": src,
		"mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// FsRemove deletes a file or empty directory, snapshotting file content first.
func FsRemove(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	path, err := resolveFsPath(params["path"])
	if err != nil {
		return nil, err
	}
	force, _ := params["force"].(bool)
	if !force {
		return nil, errors.New("force=true is required to delete")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to remove a symlink")
	}
	if info.IsDir() {
		// Only empty directories may be removed (no recursive rmdir).
		names, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("read dir: %w", err)
		}
		if len(names) > 0 {
			return nil, errors.New("directory is not empty")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove dir: %w", err)
		}
		return map[string]any{
			"ok": true, "path": path, "removed": "dir", "dir": true,
			"mtime": time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target is not a regular file or directory")
	}
	// Snapshot the content before removing so fs.restore can bring it back.
	snapshot, err := snapshotOf(path, mustRead(path, info.Size()))
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		_ = os.Remove(snapshot)
		return nil, fmt.Errorf("remove file: %w", err)
	}
	return map[string]any{
		"ok": true, "path": path, "removed": "file", "snapshot": snapshot,
		"mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// FsRestore brings back a removed file (from snapshot) or an empty directory.
func FsRestore(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	path, err := resolveFsPath(params["path"])
	if err != nil {
		return nil, err
	}
	isDir, _ := params["dir"].(bool)
	if isDir {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("restore dir: %w", err)
		}
		return map[string]any{
			"ok": true, "path": path, "restored": "dir",
			"mtime": time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	snapRaw, ok := params["snapshot"]
	if !ok {
		return nil, errors.New("snapshot is required")
	}
	snapshot, err := resolveSnapshotPath(snapRaw)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(snapshot) != fsSnapshotDir {
		return nil, errors.New("snapshot outside managed directory")
	}
	snapInfo, err := os.Lstat(snapshot)
	if err != nil {
		return nil, fmt.Errorf("stat snapshot: %w", err)
	}
	if !snapInfo.Mode().IsRegular() || snapInfo.Size() > fsSnapshotMaxBytes {
		return nil, errors.New("snapshot is not a usable regular file")
	}
	back, err := os.ReadFile(snapshot)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	// If the target already exists, snapshot its current content first (safety
	// net so a restore never silently destroys newer data).
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("target exists and is not a regular file")
		}
		if err := writeAtomicReplace(path, back); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat target: %w", err)
	} else {
		// Target was removed; recreate it with a sane mode. The temp file from
		// writeAtomicReplace starts 0600 (agent-safe default) — restore a
		// readable mode so the recovered file is usable by its owner.
		if err := writeAtomicReplace(path, back); err != nil {
			return nil, err
		}
		_ = os.Chmod(path, 0644)
	}
	if err := os.Remove(snapshot); err != nil {
		return nil, fmt.Errorf("remove snapshot: %w", err)
	}
	return map[string]any{
		"ok": true, "path": path, "restored": "file", "size": len(back),
		"mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}
