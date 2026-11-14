package agentbridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client dials the ocp-agent Unix socket. Protocol: one JSON object per line.
type Client struct {
	sock string
}

type req struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}

type resp struct {
	ID    string         `json:"id"`
	OK    bool           `json:"ok"`
	Data  map[string]any `json:"data,omitempty"`
	Error string         `json:"error,omitempty"`
}

func New(sock string) *Client { return &Client{sock: sock} }

const (
	maxBridgeRequestBytes  = 64 << 10
	maxBridgeResponseBytes = 1 << 20
)

var errBridgeFrameTooLarge = fmt.Errorf("agent response exceeds size limit")

// Call runs one whitelisted action and returns its Data.
func (c *Client) Call(action string, params map[string]any) (map[string]any, error) {
	requestBytes, err := json.Marshal(req{ID: "panel", Action: action, Params: params})
	if err != nil {
		return nil, fmt.Errorf("encode agent request: %w", err)
	}
	requestBytes = append(requestBytes, '\n')
	if len(requestBytes) > maxBridgeRequestBytes {
		return nil, fmt.Errorf("agent request exceeds size limit (%d bytes)", maxBridgeRequestBytes)
	}
	conn, err := net.DialTimeout("unix", c.sock, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("agent socket %s: %w", c.sock, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(requestBytes); err != nil {
		return nil, fmt.Errorf("write agent request: %w", err)
	}
	responseBytes, err := readResponseFrame(bufio.NewReaderSize(conn, 4096), maxBridgeResponseBytes)
	if err != nil {
		return nil, err
	}
	var r resp
	if err := json.Unmarshal(responseBytes, &r); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	if r.ID != "panel" {
		return nil, fmt.Errorf("agent response id mismatch")
	}
	if !r.OK {
		return nil, fmt.Errorf("agent %s: %s", action, r.Error)
	}
	return r.Data, nil
}

func readResponseFrame(reader *bufio.Reader, limit int) ([]byte, error) {
	var frame []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(frame)+len(part) > limit {
			return nil, errBridgeFrameTooLarge
		}
		frame = append(frame, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read agent response: %w", err)
		}
		return frame, nil
	}
}
