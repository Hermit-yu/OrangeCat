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

// P4-4 写切片：上传（新建或覆盖）。
//
// 上传走与 fs.write 相同的原子替换纪律，但允许**新建**文件（fs.write 只
// 写已存在文件，供编辑；上传要落地新文件）。目标目录必须存在；文件名拒绝
// 路径穿越（不含分隔符/..）；覆盖已存在文件时先快照。
//
// 安全模型：content 为字符串（panel 侧从 multipart 读入后转发），大小上限
// 与 fs.write 一致；文件名只允许 basename；目标目录解析用 resolveFsPath。

// FsUpload writes one file into an existing directory, creating or replacing it.
func FsUpload(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dir, err := resolveFsPath(params["path"])
	if err != nil {
		return nil, err
	}
	name, ok := params["name"].(string)
	if !ok {
		return nil, errors.New("name is required")
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return nil, errors.New("name must be a plain file name")
	}
	content, ok := params["content"].(string)
	if !ok || content == "" {
		return nil, errors.New("content is required")
	}
	if len(content) > fsWriteMaxBytes {
		return nil, fmt.Errorf("content exceeds %d bytes", fsWriteMaxBytes)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat target dir: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("target is not a real directory")
	}
	target := filepath.Join(dir, name)

	snapshot := ""
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("target exists and is not a regular file")
		}
		snapshot, err = snapshotOf(target, mustRead(target, info.Size()))
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat target: %w", err)
	}

	if err := writeAtomicReplace(target, []byte(content)); err != nil {
		_ = os.Remove(snapshot)
		return nil, err
	}
	return map[string]any{
		"ok": true, "path": target, "snapshot": snapshot,
		"size": len(content), "mtime": time.Now().UTC().Format(time.RFC3339),
	}, nil
}
