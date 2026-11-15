package actions

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/agent/internal/audit"
)

// Request/Response protocol over the Unix socket: one JSON object per line.
type Request struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

type Response struct {
	ID    string         `json:"id"`
	OK    bool           `json:"ok"`
	Data  map[string]any `json:"data,omitempty"`
	Error string         `json:"error,omitempty"`
	DurMS int64          `json:"dur_ms"`
}

// Handler runs one structured action against the host.
type Handler func(ctx context.Context, p map[string]any) (map[string]any, error)

// Registry is the action whitelist (structured parameters only, no free shell).
type Registry struct {
	handlers map[string]Handler
}

func NewRegistry() *Registry {
	r := &Registry{handlers: map[string]Handler{}}
	r.Register("system.info", noParams(SystemInfo))
	r.Register("system.metrics", noParams(SystemMetrics))
	r.Register("system.services", Services)
	r.Register("net.diagnostics", LinkDiagnostics)
	r.Register("health.check", HealthCheck)
	r.Register("process.kill", KillProcess)
	r.Register("docker.summary", noParams(DockerSummary))
	r.Register("docker.containers", noParams(DockerContainers))
	r.Register("docker.images", noParams(DockerImages))
	r.Register("docker.networks", noParams(DockerNetworks))
	r.Register("docker.volumes", noParams(DockerVolumes))
	r.Register("docker.logs", DockerLogs)
	r.Register("docker.stats", DockerStats)
	r.Register("docker.container.action", DockerContainerAction)
	r.Register("compose.projects", noParams(ComposeProjects))
	r.Register("compose.validate", ComposeValidate)
	r.Register("nginx.sites", noParams(NginxSites))
	r.Register("nginx.sites.full", noParams(NginxSitesP3))
	r.Register("nginx.test", NginxTest)
	r.Register("nginx.reload", NginxReload)
	r.Register("nginx.site.detail", NginxSiteDetail)
	r.Register("net.interfaces", noParams(NetInterfaces))
	r.Register("processes", Processes)
	r.Register("fs.list", FsList)
	r.Register("fs.read", FsRead)
	r.Register("fs.stat", FsStat)
	r.Register("fs.write", FsWrite)
	r.Register("fs.write.rollback", FsWriteRollback)
	r.Register("fs.rename", FsRename)
	r.Register("fs.remove", FsRemove)
	r.Register("fs.restore", FsRestore)
	r.Register("fs.upload", FsUpload)
	r.Register("fs.download", FsDownload)
	r.Register("task.start", TaskStart)
	r.Register("task.status", TaskStatus)
	r.Register("task.log", TaskLog)
	r.Register("pty.open", ptyOpen)
	r.Register("pty.status", ptyStatus)
	r.Register("pty.input", ptyInput)
	r.Register("pty.resize", ptyResize)
	r.Register("pty.close", ptyClose)
	r.Register("pty.list", ptyList)
	r.Register("ai.chat", AIChat)
	r.Register("ai.status", AIStatus)
	return r
}

func noParams(handler Handler) Handler {
	return func(ctx context.Context, params map[string]any) (map[string]any, error) {
		if len(params) != 0 {
			return nil, errors.New("action does not accept parameters")
		}
		return handler(ctx, params)
	}
}

func (r *Registry) Count() int { return len(r.handlers) }

func (r *Registry) Register(name string, h Handler) {
	if _, dup := r.handlers[name]; dup {
		panic("duplicate action " + name)
	}
	r.handlers[name] = h
}

// Serve wires the socket server.
func (r *Registry) Serve() *SocketServer { return &SocketServer{reg: r} }

const (
	defaultSocketMaxRequestBytes  = 64 << 10
	defaultSocketMaxResponseBytes = 1 << 20
	defaultSocketMaxConnections   = 32
	defaultSocketRequestTimeout   = 30 * time.Second
	maxSocketRequestsPerConn      = 8
)

var errSocketFrameTooLarge = errors.New("socket request exceeds size limit")

// SocketServer serves the action whitelist on a Unix socket with explicit bounds.
type SocketServer struct {
	reg              *Registry
	ln               net.Listener
	path             string
	socketInfo       os.FileInfo
	maxRequestBytes  int
	maxResponseBytes int
	maxConnections   int
	requestTimeout   time.Duration
	sem              chan struct{}
	closeOnce        sync.Once
	closeErr         error
}

// Start binds the socket. Only a stale socket may be removed; arbitrary files,
// symlinks, and symlinked parent directories are rejected without modification.
func (s *SocketServer) Start(path string, a *audit.Audit) error {
	if s.reg == nil {
		return errors.New("socket server has no action registry")
	}
	if s.ln != nil {
		return errors.New("socket server already started")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return errors.New("socket parent must be a real directory")
	}
	if current, err := os.Lstat(path); err == nil {
		if current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 {
			return errors.New("socket path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if s.maxRequestBytes <= 0 {
		s.maxRequestBytes = defaultSocketMaxRequestBytes
	}
	if s.maxResponseBytes < 128 {
		s.maxResponseBytes = defaultSocketMaxResponseBytes
	}
	if s.maxConnections <= 0 {
		s.maxConnections = defaultSocketMaxConnections
	}
	if s.requestTimeout <= 0 {
		s.requestTimeout = defaultSocketRequestTimeout
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return fmt.Errorf("set agent socket permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return fmt.Errorf("verify agent socket path: %w", err)
	}
	s.ln = ln
	s.path = path
	s.socketInfo = info
	s.sem = make(chan struct{}, s.maxConnections)
	go s.acceptLoop(a)
	return nil
}

// Close stops accepting connections and removes only the socket created by this server.
func (s *SocketServer) Close() error {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.closeErr = s.ln.Close()
		}
		if s.path != "" {
			current, err := os.Lstat(s.path)
			if err == nil && current.Mode()&os.ModeSocket != 0 && s.socketInfo != nil && os.SameFile(current, s.socketInfo) {
				if removeErr := os.Remove(s.path); removeErr != nil && s.closeErr == nil {
					s.closeErr = removeErr
				}
			}
		}
	})
	if errors.Is(s.closeErr, net.ErrClosed) {
		return nil
	}
	return s.closeErr
}

func (s *SocketServer) acceptLoop(a *audit.Audit) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
			go func() {
				defer func() { <-s.sem }()
				s.handleConn(conn, a)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *SocketServer) handleConn(conn net.Conn, a *audit.Audit) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 4096)
	for count := 0; count < maxSocketRequestsPerConn; count++ {
		_ = conn.SetDeadline(time.Now().Add(s.requestTimeout))
		frame, err := readSocketFrame(reader, s.maxRequestBytes)
		if errors.Is(err, errSocketFrameTooLarge) {
			_ = s.writeResponse(conn, Response{OK: false, Error: "request exceeds size limit"})
			return
		}
		if err != nil {
			return
		}
		var req Request
		dec := json.NewDecoder(bytes.NewReader(frame))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			_ = s.writeResponse(conn, Response{OK: false, Error: "invalid request"})
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			_ = s.writeResponse(conn, Response{ID: req.ID, OK: false, Error: "invalid request"})
			return
		}
		if req.Action == "" || len(req.Action) > 128 || len(req.ID) > 128 {
			_ = s.writeResponse(conn, Response{ID: req.ID, OK: false, Error: "invalid request fields"})
			continue
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
		response := s.dispatch(ctx, req, a)
		cancel()
		response.DurMS = time.Since(start).Milliseconds()
		if err := s.writeResponse(conn, response); err != nil {
			return
		}
	}
}

func readSocketFrame(reader *bufio.Reader, limit int) ([]byte, error) {
	var frame []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(frame)+len(part) > limit {
			return nil, errSocketFrameTooLarge
		}
		frame = append(frame, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return frame, nil
	}
}

func (s *SocketServer) writeResponse(conn net.Conn, response Response) error {
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > s.maxResponseBytes {
		data, err = json.Marshal(Response{ID: response.ID, OK: false, Error: "response exceeds size limit"})
		if err != nil {
			return err
		}
	}
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(s.requestTimeout))
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *SocketServer) dispatch(ctx context.Context, req Request, a *audit.Audit) Response {
	h, ok := s.reg.handlers[req.Action]
	if !ok {
		return Response{ID: req.ID, OK: false, Error: "action not in whitelist: " + req.Action}
	}
	data, err := h(ctx, req.Params)
	if err != nil {
		a.Record(req.Action, nil, false, err.Error(), 0)
		return Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	a.Record(req.Action, nil, true, "", 0)
	return Response{ID: req.ID, OK: true, Data: data}
}
