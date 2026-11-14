package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHandleLoginRejectsMalformedJSON(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":`))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestHandleLoginRejectsOversizedJSON(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	body := `{"username":"admin","password":"` + strings.Repeat("x", 2048) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}

func TestHandleLoginRejectsOversizedTrailingWhitespace(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	body := `{"username":"admin","password":"secret"}` + strings.Repeat(" ", 2048)
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}

func TestHandleLoginRejectsTrailingJSONValue(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"} {}`))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestHandleLoginRejectsMissingCredentials(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin"}`))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()

	p.handleLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestHandleLogoutRequiresPost(t *testing.T) {
	p := &panel{}
	r := httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	w := httptest.NewRecorder()

	p.handleLogout(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusMethodNotAllowed, w.Body.String())
	}
}

func TestHandleLogoutRequiresCSRFHeader(t *testing.T) {
	const token = "csrf-test-session"
	sessMu.Lock()
	sessions[token] = session{token: token, created: time.Now()}
	sessMu.Unlock()
	t.Cleanup(func() {
		sessMu.Lock()
		delete(sessions, token)
		sessMu.Unlock()
	})

	p := &panel{}
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()

	p.handleLogout(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestHandleLogoutRejectsForeignOrigin(t *testing.T) {
	const token = "origin-test-session"
	sessMu.Lock()
	sessions[token] = session{token: token, created: time.Now()}
	sessMu.Unlock()
	t.Cleanup(func() {
		sessMu.Lock()
		delete(sessions, token)
		sessMu.Unlock()
	})

	p := &panel{}
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.Host = "panel.example"
	r.Header.Set("Origin", "https://attacker.example")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()

	p.handleLogout(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestHandleLogoutIssuesCSRFHeader(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}, trustedProxyIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	r.RemoteAddr = "192.0.2.3:1234"
	loginResponse := httptest.NewRecorder()
	p.handleLogin(loginResponse, r)

	var sessionCookie *http.Cookie
	var csrfCookie *http.Cookie
	for _, cookie := range loginResponse.Result().Cookies() {
		switch cookie.Name {
		case "ocp_session":
			sessionCookie = cookie
		case "ocp_csrf":
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("login must issue both session and CSRF cookies before logout can be tested")
	}
	t.Cleanup(func() {
		sessMu.Lock()
		delete(sessions, sessionCookie.Value)
		sessMu.Unlock()
	})

	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logoutRequest.RemoteAddr = "192.0.2.1:1234"
	logoutRequest.AddCookie(sessionCookie)
	logoutRequest.AddCookie(csrfCookie)
	logoutRequest.Header.Set("X-CSRF-Token", csrfCookie.Value)
	logoutRequest.Host = "panel.example"
	logoutRequest.Header.Set("X-Forwarded-Proto", "https")
	logoutRequest.Header.Set("Origin", "https://panel.example")
	logoutResponse := httptest.NewRecorder()
	p.handleLogout(logoutResponse, logoutRequest)

	if logoutResponse.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", logoutResponse.Code, http.StatusOK, logoutResponse.Body.String())
	}
	sessMu.Lock()
	_, stillPresent := sessions[sessionCookie.Value]
	sessMu.Unlock()
	if stillPresent {
		t.Fatal("session remained active after a valid CSRF-protected logout")
	}
}

func TestHandleLogoutRejectsSchemeMismatch(t *testing.T) {
	p := &panel{password: "secret", attempts: map[string]int{}, trustedProxyIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}}
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	loginRequest.RemoteAddr = "192.0.2.4:1234"
	loginResponse := httptest.NewRecorder()
	p.handleLogin(loginResponse, loginRequest)

	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range loginResponse.Result().Cookies() {
		switch cookie.Name {
		case "ocp_session":
			sessionCookie = cookie
		case "ocp_csrf":
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("login must issue both cookies before Origin checks can be tested")
	}
	t.Cleanup(func() {
		sessMu.Lock()
		delete(sessions, sessionCookie.Value)
		sessMu.Unlock()
	})

	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logoutRequest.RemoteAddr = "192.0.2.1:1234"
	logoutRequest.Host = "panel.example"
	logoutRequest.Header.Set("X-Forwarded-Proto", "https")
	logoutRequest.Header.Set("Origin", "http://panel.example")
	logoutRequest.AddCookie(sessionCookie)
	logoutRequest.AddCookie(csrfCookie)
	logoutRequest.Header.Set("X-CSRF-Token", csrfCookie.Value)
	logoutResponse := httptest.NewRecorder()
	p.handleLogout(logoutResponse, logoutRequest)

	if logoutResponse.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", logoutResponse.Code, http.StatusForbidden, logoutResponse.Body.String())
	}
}

func TestHandleLoginUnlocksAfter15MinuteFailureWindow(t *testing.T) {
	current := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	p := &panel{
		password: "secret",
		attempts: map[string]int{},
		now:      func() time.Time { return current },
	}
	login := func(password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		r.RemoteAddr = "192.0.2.5:1234"
		w := httptest.NewRecorder()
		p.handleLogin(w, r)
		return w
	}
	for i := 0; i < 10; i++ {
		if got := login("wrong").Code; got != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d status = %d, want %d", i+1, got, http.StatusUnauthorized)
		}
	}
	if got := login("secret").Code; got != http.StatusTooManyRequests {
		t.Fatalf("locked login status = %d, want %d", got, http.StatusTooManyRequests)
	}

	current = current.Add(15*time.Minute + time.Second)
	w := login("secret")
	if w.Code != http.StatusOK {
		t.Fatalf("login after failure window status = %d, want %d; body=%q", w.Code, http.StatusOK, w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "ocp_session" {
			t.Cleanup(func() {
				sessMu.Lock()
				delete(sessions, cookie.Value)
				sessMu.Unlock()
			})
		}
	}
}

func TestHandleLoginBoundsTrackedFailureIPs(t *testing.T) {
	p := &panel{
		password: "secret",
		attempts: map[string]int{},
		now:      func() time.Time { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) },
	}
	for i := 0; i < 4097; i++ {
		host := "198.51." + strconv.Itoa(100+i/256) + "." + strconv.Itoa(i%256)
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		r.RemoteAddr = host + ":1234"
		p.handleLogin(httptest.NewRecorder(), r)
	}
	if got := len(p.attempts); got > 4096 {
		t.Fatalf("tracked failure IPs = %d, want at most 4096", got)
	}
	if got := len(p.attemptWindow); got > 4096 {
		t.Fatalf("tracked failure windows = %d, want at most 4096", got)
	}
}

func TestClientIPUsesForwardedIPOnlyForTrustedProxy(t *testing.T) {
	p := &panel{trustedProxyIPs: map[netip.Addr]struct{}{netip.MustParseAddr("172.18.0.6"): {}}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "172.18.0.6:40123"
	r.Header.Set("X-Real-IP", "198.51.100.42")
	if got := p.clientIP(r); got != "198.51.100.42" {
		t.Fatalf("clientIP = %q, want trusted forwarded IP", got)
	}
}

func TestClientIPIgnoresForwardedIPFromUntrustedPeer(t *testing.T) {
	p := &panel{trustedProxyIPs: map[netip.Addr]struct{}{netip.MustParseAddr("172.18.0.6"): {}}}
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "172.18.0.7:40123"
	r.Header.Set("X-Real-IP", "198.51.100.42")
	if got := p.clientIP(r); got != "172.18.0.7" {
		t.Fatalf("clientIP = %q, want remote peer IP", got)
	}
}

func TestParseTrustedProxyIPsRequiresExactAddresses(t *testing.T) {
	ips, err := parseTrustedProxyIPs("172.18.0.6, 2001:db8::1")
	if err != nil {
		t.Fatalf("parseTrustedProxyIPs returned error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("parsed trusted proxy count = %d, want 2", len(ips))
	}
	if _, err := parseTrustedProxyIPs("172.18.0.0/16"); err == nil {
		t.Fatal("CIDR must be rejected; trust only exact reverse-proxy IPs")
	}
}

func TestRequireAuthDeletesExpiredSession(t *testing.T) {
	const token = "expired-session"
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	sessMu.Lock()
	oldSessions := sessions
	sessions = map[string]session{token: {token: token, csrf: "csrf", created: now.Add(-13 * time.Hour)}}
	sessMu.Unlock()
	t.Cleanup(func() {
		sessMu.Lock()
		sessions = oldSessions
		sessMu.Unlock()
	})

	p := &panel{}
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	w := httptest.NewRecorder()
	p.requireAuth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	sessMu.Lock()
	_, stillPresent := sessions[token]
	sessMu.Unlock()
	if stillPresent {
		t.Fatal("expired session remains in the global session table")
	}
}

func TestHandleLoginBoundsSessionTable(t *testing.T) {
	sessMu.Lock()
	oldSessions := sessions
	sessions = make(map[string]session)
	sessMu.Unlock()
	t.Cleanup(func() {
		sessMu.Lock()
		sessions = oldSessions
		sessMu.Unlock()
	})

	p := &panel{password: "secret", attempts: map[string]int{}}
	for i := 0; i < 4097; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
		r.RemoteAddr = "192.0.2.8:1234"
		w := httptest.NewRecorder()
		p.handleLogin(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("login %d status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}
	sessMu.Lock()
	got := len(sessions)
	sessMu.Unlock()
	if got > 4096 {
		t.Fatalf("session table size = %d, want at most 4096", got)
	}
}

func TestHandleIndexUsesNonceCSPWithoutInlineAttributes(t *testing.T) {
	p := &panel{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	p.handleIndex(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP must use nonce sources and omit unsafe-inline, got %q", csp)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nonce=") {
		t.Fatal("embedded script/style nonce missing from page")
	}
	if strings.Contains(body, "onclick=") || strings.Contains(body, "style=") {
		t.Fatal("page still depends on inline event handlers or style attributes")
	}
}

func TestHandleLogoutRejectsUntrustedForwardedProto(t *testing.T) {
	const token = "spoofed-forwarded-proto-session"
	sessMu.Lock()
	sessions[token] = session{token: token, csrf: "csrf-value", created: time.Now()}
	sessMu.Unlock()
	t.Cleanup(func() { deleteSession(token) })

	p := &panel{}
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.RemoteAddr = "198.51.100.99:4321"
	r.Host = "panel.example"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://panel.example")
	r.AddCookie(&http.Cookie{Name: "ocp_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "ocp_csrf", Value: "csrf-value"})
	r.Header.Set("X-CSRF-Token", "csrf-value")
	w := httptest.NewRecorder()
	p.handleLogout(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; untrusted X-Forwarded-Proto must not set request scheme", w.Code, http.StatusForbidden)
	}
}

func TestSecurityHeadersCoverSuccessAndErrorResponses(t *testing.T) {
	p := &panel{}
	for _, status := range []int{http.StatusOK, http.StatusNotFound} {
		handler := p.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		for header, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cache-Control":                "no-store",
		} {
			if got := w.Header().Get(header); got != want {
				t.Errorf("status %d: %s = %q, want %q", status, header, got, want)
			}
		}
		if got := w.Header().Get("Content-Security-Policy"); got == "" {
			t.Errorf("status %d: Content-Security-Policy missing", status)
		}
	}
}

func TestLoadTrustedProxyIPsFileRequiresNonemptyExactAddresses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trusted-proxies")
	if err := os.WriteFile(path, []byte("172.18.0.6\n2001:db8::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadTrustedProxyIPsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d trusted IPs, want 2", len(got))
	}
	for _, raw := range []string{"", "10.0.0.0/24", "172.18.0.6,", "999.1.1.1"} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTrustedProxyIPsFile(path); err == nil {
			t.Errorf("trusted proxy file accepted %q", raw)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("127.0.0.1\n", 65)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedProxyIPsFile(path); err == nil {
		t.Fatal("trusted proxy file accepted more than 64 entries")
	}
	if err := os.WriteFile(path, []byte("127.0.0.1"+strings.Repeat(" ", 4096)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedProxyIPsFile(path); err == nil {
		t.Fatal("trusted proxy file accepted more than 4096 bytes")
	}
}

func TestReadPasswordFileTrimsTrailingLineEndings(t *testing.T) {
	for name, content := range map[string]string{
		"lf":   "generated-secret\n",
		"crlf": "generated-secret\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "panel-password")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := readPasswordFile(path); err != nil || got != "generated-secret" {
				t.Fatalf("readPasswordFile = %q, %v; want generated-secret", got, err)
			}
		})
	}
}

func TestReadPasswordFileRequiresPrivateRegularNonemptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "panel-password")
	if _, err := readPasswordFile(path); !os.IsNotExist(err) {
		t.Fatalf("missing password file error = %v, want not-exist", err)
	}
	if err := os.WriteFile(path, []byte("generated-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readPasswordFile(path); err != nil || got != "generated-secret" {
		t.Fatalf("readPasswordFile = %q, %v", got, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(path); err == nil {
		t.Fatal("password file readable by group/others was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(path); err == nil {
		t.Fatal("empty password file was accepted")
	}
	symlink := filepath.Join(dir, "password-link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(symlink); err == nil {
		t.Fatal("password file symlink was accepted")
	}
}
