package actions

import (
	"encoding/json"
	"net"
	"os"
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
type Handler func(p map[string]any) (map[string]any, error)

// Registry is the action whitelist (structured parameters only, no free shell).
type Registry struct {
	handlers map[string]Handler
}

func NewRegistry() *Registry {
	r := &Registry{handlers: map[string]Handler{}}
	r.Register("system.info", SystemInfo)
	r.Register("system.metrics", SystemMetrics)
	r.Register("docker.summary", DockerSummary)
	r.Register("docker.containers", DockerContainers)
	r.Register("nginx.sites", NginxSites)
	r.Register("net.interfaces", NetInterfaces)
	r.Register("processes", Processes)
	return r
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

// SocketServer serves the action whitelist on a unix socket.
type SocketServer struct {
	reg *Registry
	ln  net.Listener
}

// Start binds the socket and serves. Stale sockets are replaced (single writer invariant).
func (s *SocketServer) Start(path string, a *audit.Audit) error {
	if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0660)
	s.ln = ln
	go s.acceptLoop(a)
	return nil
}

func (s *SocketServer) acceptLoop(a *audit.Audit) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, a)
	}
}

func (s *SocketServer) handleConn(conn net.Conn, a *audit.Audit) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			return
		}
		start := time.Now()
		resp := s.dispatch(req, a)
		resp.DurMS = time.Since(start).Milliseconds()
		enc.Encode(resp)
	}
}

func (s *SocketServer) dispatch(req Request, a *audit.Audit) Response {
	h, ok := s.reg.handlers[req.Action]
	if !ok {
		return Response{ID: req.ID, OK: false, Error: "action not in whitelist: " + req.Action}
	}
	data, err := h(req.Params)
	if err != nil {
		a.Record(req.Action, req.Params, false, err.Error(), 0)
		return Response{ID: req.ID, OK: false, Error: err.Error()}
	}
	a.Record(req.Action, req.Params, true, "", 0)
	return Response{ID: req.ID, OK: true, Data: data}
}
