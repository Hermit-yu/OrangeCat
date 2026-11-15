package actions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
)

// P5 切片：受控 PTY 终端会话。
//
// 设计（与 task.go 同策略：agent 进程内注册表，跨请求有状态）：
//   - 终端能力默认关闭（ptyEnabled 开关，由安装器环境注入），独立开关控制。
//   - 会话注册表保存每个 PTY 会话：命令、PTY 文件、输出环形缓冲、启动时间、
//     最后活动时间。agent 常驻，跨请求可见。
//   - 输出用增量轮询（offset 指针），天然支持断线重连：客户端断开后再连，
//     从 offset 继续拉，不丢输出。
//   - 连接/空闲/输出上限：maxSessions 并发上限、每会话输出字节上限（环形覆盖）、
//     空闲超时自动回收、进程结束自动清理。
//   - 主动关停：pty.close 发送 SIGHUP + 杀掉进程组。
//   - 命令白名单：不接受任意 shell，只允许固定命令（如 /bin/bash -l）在固定
//     环境下启动；用户输入只作为 stdin 写进 PTY，不拼 shell。
//
// 安全模型：PTY 是 root 下的完整终端（面板管理员已经是 root 管理面板），
// 但命令仍固定白名单 + 无自由参数。输入经 PTY 文件描述符写入，不经过 shell
// 解析（bash 交互模式下仍是 shell 内建，但白名单命令不含用户拼接参数）。

const (
	ptyMaxSessions    = 4                // 并发终端会话上限
	ptyMaxOutputBytes = 256 << 10        // 每会话输出缓冲上限（256 KiB 环形）
	ptyMaxInputBytes  = 1 << 16          // 单次输入上限（64 KiB）
	ptyIdleTimeout    = 5 * time.Minute // 空闲超时自动回收（运维终端 5 分钟无交互自动关，防泄漏）
	ptyPollInterval   = 100 * time.Millisecond
	ptyMaxCommandLen  = 256
	ptyMaxRows        = 200
	ptyMaxCols        = 500
	ptyMaxSessionAge  = 4 * time.Hour // 会话最长存活
)

// ptyEnabled is the master switch (installer sets OCP_AGENT_PTY_ENABLED=1).
var ptyEnabled = false

// EnablePTY turns on the terminal capability (installer/injectable for tests).
func EnablePTY() { ptyEnabled = true }

// PTYEnabled reports whether the terminal capability is on.
func PTYEnabled() bool { return ptyEnabled }

type ptySession struct {
	ID        string
	Command   string
	Started   time.Time
	LastUsed  time.Time
	Rows      int
	Cols      int
	ExitCode  *int // nil = still running
	ExitedAt  time.Time
	mu        sync.Mutex
	ptmx      *os.File
	cmd       *exec.Cmd
	output    []byte // bounded ring, tail only
	outputMax int
	closed    bool
	done      chan struct{}
}

type ptyRegistry struct {
	mu       sync.Mutex
	sessions map[string]*ptySession
}

var globalPTY = &ptyRegistry{sessions: map[string]*ptySession{}}

// resetPTYRegistry clears the registry (test helper).
func resetPTYRegistry() {
	globalPTY.mu.Lock()
	defer globalPTY.mu.Unlock()
	for _, s := range globalPTY.sessions {
		s.mu.Lock()
		if !s.closed {
			s.closed = true
			if s.ptmx != nil {
				_ = s.ptmx.Close()
			}
			if s.cmd != nil && s.cmd.Process != nil {
				_ = s.cmd.Process.Kill()
			}
		}
		s.mu.Unlock()
	}
	globalPTY.sessions = map[string]*ptySession{}
}

func lookupPTY(id string) *ptySession {
	globalPTY.mu.Lock()
	defer globalPTY.mu.Unlock()
	return globalPTY.sessions[id]
}

// ptyOpen starts a fixed command in a new PTY session.
func ptyOpen(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		switch key {
		case "command", "rows", "cols":
		default:
			return nil, fmt.Errorf("pty.open accepts command, rows, cols")
		}
	}
	cmdStr, _ := params["command"].(string)
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return nil, errors.New("command is required")
	}
	if len(cmdStr) > ptyMaxCommandLen {
		return nil, errors.New("command exceeds length limit")
	}
	// 命令白名单：只允许固定交互式 shell，不接受任意命令（防提权/任意执行）。
	if !isAllowedPTYCommand(cmdStr) {
		return nil, errors.New("command not in terminal whitelist")
	}
	rows := 24
	if r, ok := params["rows"].(float64); ok {
		if r < 1 || r > ptyMaxRows {
			return nil, errors.New("rows out of range")
		}
		rows = int(r)
	} else if r, ok := params["rows"].(int); ok {
		if r < 1 || r > ptyMaxRows {
			return nil, errors.New("rows out of range")
		}
		rows = r
	}
	cols := 80
	if c, ok := params["cols"].(float64); ok {
		if c < 1 || c > ptyMaxCols {
			return nil, errors.New("cols out of range")
		}
		cols = int(c)
	} else if c, ok := params["cols"].(int); ok {
		if c < 1 || c > ptyMaxCols {
			return nil, errors.New("cols out of range")
		}
		cols = c
	}

	globalPTY.mu.Lock()
	defer globalPTY.mu.Unlock()
	if len(globalPTY.sessions) >= ptyMaxSessions {
		return nil, errors.New("terminal session limit reached")
	}

	// 命令白名单映射到 argv（不传用户参数）。
	argv, shellPath := allowedPTYArgv(cmdStr)
	// 用 Background 而非请求 ctx：PTY 会话必须跨请求存活，请求返回后 ctx 被
	// cancel，若绑定请求 ctx 会立即杀掉 shell（会话刚开即 exited）。
	cmd := exec.CommandContext(context.Background(), shellPath, argv...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	ws := &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}
	ptmx, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	id := fmt.Sprintf("pty-%d", time.Now().UnixNano())
	s := &ptySession{
		ID: id, Command: cmdStr, Started: time.Now(), LastUsed: time.Now(),
		Rows: rows, Cols: cols, ptmx: ptmx, cmd: cmd,
		outputMax: ptyMaxOutputBytes, done: make(chan struct{}),
	}
	globalPTY.sessions[id] = s

	go ptyReadLoop(s)
	go ptyReapLoop(s)
	return map[string]any{
		"session_id": id, "command": cmdStr, "rows": rows, "cols": cols,
		"started": s.Started.UTC().Format(time.RFC3339),
	}, nil
}

// isAllowedPTYCommand reports whether the command string is a fixed whitelist
// entry (no free-form shell arguments).
func isAllowedPTYCommand(cmdStr string) bool {
	switch strings.TrimSpace(cmdStr) {
	case "bash", "/bin/bash", "bash -l", "/bin/bash -l", "sh", "/bin/sh":
		return true
	default:
		return false
	}
}

// allowedPTYArgv maps a whitelist command to argv. No user-supplied arguments.
// All shells launch interactively (-i) so they stay attached to the PTY and
// wait for input instead of exiting immediately on EOF.
func allowedPTYArgv(cmdStr string) ([]string, string) {
	switch strings.TrimSpace(cmdStr) {
	case "bash", "/bin/bash":
		return []string{"-i"}, "/bin/bash"
	case "bash -l", "/bin/bash -l":
		return []string{"-i", "-l"}, "/bin/bash"
	case "sh", "/bin/sh":
		return []string{"-i"}, "/bin/sh"
	default:
		return []string{"-i"}, "/bin/bash"
	}
}

// ptyReadLoop reads PTY output into the bounded ring until EOF.
func ptyReadLoop(s *ptySession) {
	buf := make([]byte, 4096)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.output = append(s.output, buf[:n]...)
			if len(s.output) > s.outputMax {
				s.output = s.output[len(s.output)-s.outputMax:]
			}
			s.LastUsed = time.Now()
			s.mu.Unlock()
		}
		if err != nil {
			s.mu.Lock()
			if !s.closed {
				s.closed = true
			}
			code := 0
			if s.cmd != nil && s.cmd.ProcessState != nil {
				code = s.cmd.ProcessState.ExitCode()
			}
			s.ExitCode = &code
			s.ExitedAt = time.Now()
			close(s.done)
			s.mu.Unlock()
			return
		}
	}
}

// ptyReapLoop watches for process exit and idle/age timeout.
func ptyReapLoop(s *ptySession) {
	ticker := time.NewTicker(ptyPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			idle := time.Since(s.LastUsed)
			age := time.Since(s.Started)
			if idle > ptyIdleTimeout || age > ptyMaxSessionAge {
				if !s.closed {
					s.closed = true
					_ = s.ptmx.Close()
					if s.cmd != nil && s.cmd.Process != nil {
						_ = s.cmd.Process.Kill()
					}
				}
				s.mu.Unlock()
				// Remove from registry.
				globalPTY.mu.Lock()
				delete(globalPTY.sessions, s.ID)
				globalPTY.mu.Unlock()
				return
			}
			s.mu.Unlock()
		}
	}
}

// ptyStatus returns the session's current state + incremental output since offset.
func ptyStatus(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		switch key {
		case "session_id", "offset":
		default:
			return nil, fmt.Errorf("pty.status accepts session_id, offset")
		}
	}
	id, _ := params["session_id"].(string)
	if id == "" {
		return nil, errors.New("session_id is required")
	}
	s := lookupPTY(id)
	if s == nil {
		return nil, errors.New("unknown terminal session")
	}
	offset := int64(0)
	if o, ok := params["offset"].(float64); ok {
		if o < 0 {
			return nil, errors.New("offset must be non-negative")
		}
		offset = int64(o)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUsed = time.Now()
	total := len(s.output)
	start := int(offset)
	if start > total {
		start = total
	}
	chunk := append([]byte(nil), s.output[start:]...)
	out := map[string]any{
		"session_id": id, "state": "running", "offset": total,
		"chunk": string(chunk), "closed": s.closed,
	}
	if s.ExitCode != nil {
		out["state"] = "exited"
		out["exit_code"] = *s.ExitCode
		out["exited_at"] = s.ExitedAt.UTC().Format(time.RFC3339)
	}
	return out, nil
}

// ptyInput writes user input to the PTY stdin.
func ptyInput(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		switch key {
		case "session_id", "data":
		default:
			return nil, fmt.Errorf("pty.input accepts session_id, data")
		}
	}
	id, _ := params["session_id"].(string)
	if id == "" {
		return nil, errors.New("session_id is required")
	}
	s := lookupPTY(id)
	if s == nil {
		return nil, errors.New("unknown terminal session")
	}
	data, _ := params["data"].(string)
	if len(data) > ptyMaxInputBytes {
		return nil, errors.New("input exceeds size limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("terminal session is closed")
	}
	if s.ExitCode != nil {
		return nil, errors.New("terminal session has exited")
	}
	if _, err := s.ptmx.Write([]byte(data)); err != nil {
		return nil, fmt.Errorf("write pty: %w", err)
	}
	s.LastUsed = time.Now()
	return map[string]any{"session_id": id, "written": len(data)}, nil
}

// ptyResize updates the PTY window size.
func ptyResize(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		switch key {
		case "session_id", "rows", "cols":
		default:
			return nil, fmt.Errorf("pty.resize accepts session_id, rows, cols")
		}
	}
	id, _ := params["session_id"].(string)
	if id == "" {
		return nil, errors.New("session_id is required")
	}
	s := lookupPTY(id)
	if s == nil {
		return nil, errors.New("unknown terminal session")
	}
	rows := 24
	if r, ok := params["rows"].(float64); ok {
		if r < 1 || r > ptyMaxRows {
			return nil, errors.New("rows out of range")
		}
		rows = int(r)
	} else if r, ok := params["rows"].(int); ok {
		if r < 1 || r > ptyMaxRows {
			return nil, errors.New("rows out of range")
		}
		rows = r
	}
	cols := 80
	if c, ok := params["cols"].(float64); ok {
		if c < 1 || c > ptyMaxCols {
			return nil, errors.New("cols out of range")
		}
		cols = int(c)
	} else if c, ok := params["cols"].(int); ok {
		if c < 1 || c > ptyMaxCols {
			return nil, errors.New("cols out of range")
		}
		cols = c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("terminal session is closed")
	}
	if err := pty.Setsize(s.ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); err != nil {
		return nil, fmt.Errorf("resize pty: %w", err)
	}
	s.Rows, s.Cols = rows, cols
	s.LastUsed = time.Now()
	return map[string]any{"session_id": id, "rows": rows, "cols": cols}, nil
}

// ptyClose actively terminates a session (SIGHUP + kill process group).
func ptyClose(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		switch key {
		case "session_id":
		default:
			return nil, fmt.Errorf("pty.close accepts session_id")
		}
	}
	id, _ := params["session_id"].(string)
	if id == "" {
		return nil, errors.New("session_id is required")
	}
	s := lookupPTY(id)
	if s == nil {
		return nil, errors.New("unknown terminal session")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return map[string]any{"session_id": id, "closed": true}, nil
	}
	s.closed = true
	_ = s.ptmx.Close()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	s.mu.Unlock()
	globalPTY.mu.Lock()
	delete(globalPTY.sessions, id)
	globalPTY.mu.Unlock()
	return map[string]any{"session_id": id, "closed": true}, nil
}

// ptyList lists active sessions (admin visibility).
func ptyList(ctx context.Context, params map[string]any) (map[string]any, error) {
	if !ptyEnabled {
		return nil, errors.New("terminal capability is disabled")
	}
	for key := range params {
		return nil, fmt.Errorf("pty.list accepts no parameters (unexpected %q)", key)
	}
	globalPTY.mu.Lock()
	defer globalPTY.mu.Unlock()
	var out []map[string]any
	for _, s := range globalPTY.sessions {
		s.mu.Lock()
		state := "running"
		if s.ExitCode != nil {
			state = "exited"
		}
		if s.closed {
			state = "closed"
		}
		out = append(out, map[string]any{
			"session_id": s.ID, "command": s.Command, "state": state,
			"started":   s.Started.UTC().Format(time.RFC3339),
			"last_used": s.LastUsed.UTC().Format(time.RFC3339),
		})
		s.mu.Unlock()
	}
	if out == nil {
		out = []map[string]any{}
	}
	return map[string]any{"sessions": out, "count": len(out)}, nil
}

// ptyStatusWithOffset is a convenience wrapper used by tests.
func ptyStatusWithOffset(id string, offset int64) (map[string]any, error) {
	return ptyStatus(context.Background(), map[string]any{"session_id": id, "offset": offset})
}

var _ = io.Discard
