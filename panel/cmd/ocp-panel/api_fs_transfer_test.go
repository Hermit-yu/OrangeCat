package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

func fsUploadReq(t *testing.T, p *panel, dir, filename, content string) *httptest.ResponseRecorder {
	t.Helper()
	token, csrf := seededSession(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", dir)
	fw, _ := mw.CreateFormFile("file", filename)
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/fs/upload", &body)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleFsUpload(w, r)
	return w
}

func TestFsUploadSuccessAndAgentRelay(t *testing.T) {
	sock, got := fakeAgent(t, map[string]any{"ok": true, "path": "/tmp/u.txt"})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	w := fsUploadReq(t, p, "/tmp", "u.txt", "hello-upload")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got.Action != "fs.upload" {
		t.Fatalf("agent action = %q", got.Action)
	}
	if got.Params["name"] != "u.txt" || got.Params["content"] != "hello-upload" {
		t.Fatalf("relay params = %v", got.Params)
	}
	if len(audit.events) != 1 || audit.events[0].Reason != authaudit.ReasonFsUploadSent {
		t.Fatalf("audit = %+v", audit.events)
	}
}

func TestFsUploadRejectsTraversalName(t *testing.T) {
	sock, _ := fakeAgent(t, map[string]any{})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	// filename with slash is rejected at panel layer (filepath.Base check).
	w := fsUploadReq(t, p, "/tmp", "../evil.txt", "x")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["ok"] != false {
		t.Fatalf("traversal filename accepted: %s", w.Body.String())
	}
}

func TestFsDownloadStreamsContent(t *testing.T) {
	raw := "binary\x00data\x01"
	sock, _ := fakeAgent(t, map[string]any{
		"path": "/tmp/b.bin", "content_b64": base64.StdEncoding.EncodeToString([]byte(raw)),
		"size": len(raw), "binary": true,
	})
	audit := &capturedAuthAudit{}
	p := &panel{password: "secret", attempts: map[string]int{}, authAudit: audit, clients: agentbridge.New(sock)}
	token, csrf := seededSession(t)
	r := httptest.NewRequest(http.MethodGet, "/api/fs/download?path=/tmp/b.bin", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Host = "localhost:8390"
	r.Header.Set("Origin", "http://localhost:8390")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: csrf})
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.handleFsDownload(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "b.bin") {
		t.Fatalf("disposition = %q", cd)
	}
	if w.Body.String() != raw {
		t.Fatalf("body mismatch: got %q want %q", w.Body.String(), raw)
	}
}
