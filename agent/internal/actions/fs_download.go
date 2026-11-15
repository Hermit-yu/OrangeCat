package actions

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"
)

// P4-4 只读切片：下载（返回 base64 内容，含二进制）。
//
// 与 fs.read 不同，下载允许二进制文件——它以 base64 字符串返回内容，由
// panel 侧解码后以 octet-stream 流回。大小上限与 read 一致（有界，防一次
// 拉爆内存）。拒绝目录与符号链接（防通过下载接口读任意链接目标）。

const fsDownloadMaxBytes = 256 << 10

// FsDownload returns one file's bytes base64-encoded with a binary flag.
func FsDownload(ctx context.Context, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	path, err := resolveFsPath(params["path"])
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
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to download through a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > fsDownloadMaxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", fsDownloadMaxBytes)
	}
	buf := make([]byte, info.Size())
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return map[string]any{
		"path": path, "content_b64": base64.StdEncoding.EncodeToString(buf[:n]),
		"size": n, "binary": true, "mtime": info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}
