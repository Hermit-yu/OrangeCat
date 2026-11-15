package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/agentbridge"
	"github.com/Hermit-yu/OrangeCatPanel/panel/internal/authaudit"
)

//go:embed web/index.html
var webFS embed.FS

// 单管理员：用户名固定 admin，密码首启生成，0600 落盘，永不进日志（R8）。
type panel struct {
	sock            string
	password        string
	pwPath          string // 切片 F：panel-password 文件路径（改密码写回）
	clients         *agentbridge.Client
	mu              sync.Mutex
	attempts        map[string]int // IP -> 15 分钟窗口内的登录尝试数
	attemptWindow   map[string]time.Time
	trustedProxyIPs map[netip.Addr]struct{}
	authAudit       interface{ Record(authaudit.Event) error }
	auditPath       string // 切片 E：auth-audit.jsonl 路径（安全审计标签页）
	now             func() time.Time // 可注入时钟，便于确定性验证限速窗口
	aiEnabled       bool             // 切片 A：AI 助手能力是否启用（OCP_PANEL_AI_ENABLED=1）
}

func (p *panel) newClient() *agentbridge.Client { return p.clients }

func main() {
	addr := flag.String("addr", "127.0.0.1:8390", "listen address (R4: 默认只绑内网)")
	sock := flag.String("sock", "/run/ocp/agent.sock", "ocp-agent unix socket")
	pwPath := flag.String("password-file", "/var/lib/ocp/panel-password", "admin password file (0600)")
	trustedProxyIPsRaw := flag.String("trusted-proxy-ips", "", "exact IP addresses of reverse proxies allowed to supply X-Real-IP")
	trustedProxyFile := flag.String("trusted-proxy-file", "", "root-managed file containing exact trusted proxy IPs (one per line)")
	authAuditPath := flag.String("auth-audit-file", "/var/log/ocp-panel/auth-audit.jsonl", "bounded authentication audit JSONL path")
	authAuditMaxBytes := flag.Int64("auth-audit-max-bytes", 1<<20, "maximum bytes per authentication audit file")
	flag.Parse()

	if *trustedProxyFile != "" && strings.TrimSpace(*trustedProxyIPsRaw) != "" {
		log.Fatal("请只使用 --trusted-proxy-file 或 --trusted-proxy-ips 其中一种")
	}
	var trustedProxyIPs map[netip.Addr]struct{}
	var err error
	if *trustedProxyFile != "" {
		trustedProxyIPs, err = loadTrustedProxyIPsFile(*trustedProxyFile)
	} else {
		trustedProxyIPs, err = parseTrustedProxyIPs(*trustedProxyIPsRaw)
	}
	if err != nil {
		log.Fatalf("解析可信反向代理地址失败: %v", err)
	}
	auditWriter, err := authaudit.New(*authAuditPath, *authAuditMaxBytes)
	if err != nil {
		log.Fatalf("初始化认证审计失败: %v", err)
	}
	defer func() {
		if err := auditWriter.Close(); err != nil {
			log.Printf("关闭认证审计失败: %v", err)
		}
	}()
	p := &panel{sock: *sock, password: "", pwPath: *pwPath, attempts: map[string]int{}, trustedProxyIPs: trustedProxyIPs, authAudit: auditWriter, auditPath: *authAuditPath, aiEnabled: os.Getenv("OCP_PANEL_AI_ENABLED") == "1"}
	p.clients = agentbridge.New(*sock)

	// 密码：存在则严格读取；仅确认为不存在时才生成，绝不覆盖坏权限/空文件/符号链接。
	if existing, err := readPasswordFile(*pwPath); err == nil {
		p.password = existing
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("读取管理员密码文件失败: %v", err)
	} else {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("生成管理员密码失败: %v", err)
		}
		p.password = hex.EncodeToString(buf)
		if err := os.MkdirAll(dirOf(*pwPath), 0700); err != nil {
			log.Fatalf("创建密码目录失败: %v", err)
		}
		if err := os.WriteFile(*pwPath, []byte(p.password), 0600); err != nil {
			log.Fatalf("写入密码文件失败: %v", err)
		}
		fmt.Printf("已生成管理员密码写入 %s (0600)，请妥善保存，不会再显示\n", *pwPath)
	}

	// agent 探活（不致命：面板起来，数据 API 报 agent 未连接）
	if _, err := p.clients.Call("system.info", nil); err != nil {
		log.Printf("警告: ocp-agent 暂不可达 (%v)，数据 API 将报错直至 agent 上线", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", p.handleLogin)
	mux.HandleFunc("/api/logout", p.handleLogout)
	mux.HandleFunc("/api/overview", p.requireAuth(p.handleOverview))
	mux.HandleFunc("/api/docker", p.requireAuth(p.handleDocker))
	mux.HandleFunc("/api/nginx", p.requireAuth(p.handleNginx))
	mux.HandleFunc("/api/net", p.requireAuth(p.handleNet))
	mux.HandleFunc("/api/processes", p.requireAuth(p.handleProcesses))
	mux.HandleFunc("/api/services", p.requireAuth(p.handleServices))
	mux.HandleFunc("/api/health", p.requireAuth(p.handleHealth))
	mux.HandleFunc("/api/diagnostics", p.requireAuth(p.handleDiagnostics))
	mux.HandleFunc("/api/audit", p.requireAuth(p.handleAudit))
	// P7：审计导出（CSV/JSONL 下载，只读）
	mux.HandleFunc("/api/audit/export", p.requireAuth(p.handleAuditExport))
	// P7：metrics.db 在线备份/列表/恢复（写门 + 审计）
	mux.HandleFunc("/api/backup/create", p.handleBackupCreate)
	mux.HandleFunc("/api/backup/list", p.requireAuth(p.handleBackupList))
	mux.HandleFunc("/api/backup/restore", p.handleBackupRestore)
	// P7：nginx access log 分析（只读，真实日志）
	mux.HandleFunc("/api/nginx/log", p.requireAuth(p.handleNginxLog))
	// P7：Telegram 通知（status 只读；test/alert 写门 + 审计）
	mux.HandleFunc("/api/notify/status", p.requireAuth(p.handleNotifyStatus))
	mux.HandleFunc("/api/notify/test", p.handleNotifyTest)
	mux.HandleFunc("/api/notify/alert", p.handleNotifyAlert)
	// P8：集群节点（只读真实本机 + 单机诚实）
	mux.HandleFunc("/api/cluster/nodes", p.requireAuth(p.handleClusterNodes))
	mux.HandleFunc("/api/cluster/node", p.requireAuth(p.handleClusterNodeDetail))
	mux.HandleFunc("/api/cluster/pair", p.handleClusterPair)
	// P9：公开只读分享（share page 未登录可访问；create/list/revoke 管理）
	mux.HandleFunc("/share/", p.handleSharePage)
	mux.HandleFunc("/api/share/create", p.handleShareCreate)
	mux.HandleFunc("/api/share/list", p.requireAuth(p.handleShareList))
	mux.HandleFunc("/api/share/revoke", p.handleShareRevoke)
	// P9：TOTP 两步验证（setup/enable/disable 写门；status 只读）
	mux.HandleFunc("/api/totp/status", p.requireAuth(p.handleTOTPStatus))
	mux.HandleFunc("/api/totp/setup", p.handleTOTPSetup)
	mux.HandleFunc("/api/totp/enable", p.handleTOTPEnable)
	mux.HandleFunc("/api/totp/disable", p.handleTOTPDisable)
	mux.HandleFunc("/api/password", p.requireAuth(p.handleChangePassword))
	mux.HandleFunc("/api/processes/kill", p.handleProcessKill)
	mux.HandleFunc("/api/history", p.requireAuth(p.handleHistory))
	// P2：Docker 从只读到可管理
	mux.HandleFunc("/api/docker/images", p.requireAuth(p.handleDockerImages))
	mux.HandleFunc("/api/docker/networks", p.requireAuth(p.handleDockerNetworks))
	mux.HandleFunc("/api/docker/volumes", p.requireAuth(p.handleDockerVolumes))
	mux.HandleFunc("/api/docker/logs", p.requireAuth(p.handleDockerLogs))
	mux.HandleFunc("/api/docker/stats", p.requireAuth(p.handleDockerStats))
	mux.HandleFunc("/api/compose/projects", p.requireAuth(p.handleComposeProjects))
	mux.HandleFunc("/api/compose/validate", p.requireAuth(p.handleComposeValidate))
	mux.HandleFunc("/api/compose/status", p.requireAuth(p.handleComposeStatus))
	mux.HandleFunc("/api/docker/action", p.handleContainerAction)
	// P3：Nginx 站点与证书发现 + test/reload 写操作
	mux.HandleFunc("/api/nginx/full", p.requireAuth(p.handleNginxFull))
	mux.HandleFunc("/api/nginx/site", p.requireAuth(p.handleNginxSiteDetail))
	mux.HandleFunc("/api/nginx/action", p.handleNginxAction)
	// P6：站点变更写（创建/更新/删除反代 vhost，三重门 + 审计 + 回滚）
	mux.HandleFunc("/api/nginx/site/validate", p.handleNginxSiteValidate)
	mux.HandleFunc("/api/nginx/site/save", p.handleNginxSiteSave)
	mux.HandleFunc("/api/nginx/site/delete", p.handleNginxSiteDelete)
	// P6：系统管理写（主机名/时区 dry_run 预览 + 应用；SSH 只读核对）
	mux.HandleFunc("/api/system/hostname", p.handleSystemHostname)
	mux.HandleFunc("/api/system/timezone", p.handleSystemTimezone)
	mux.HandleFunc("/api/system/ssh", p.requireAuth(p.handleSystemSSH))
	mux.HandleFunc("/api/fs/list", p.requireAuth(p.handleFsList))
	mux.HandleFunc("/api/fs/read", p.requireAuth(p.handleFsRead))
	mux.HandleFunc("/api/fs/stat", p.requireAuth(p.handleFsStat))
	mux.HandleFunc("/api/fs/write", p.handleFsWrite)
	mux.HandleFunc("/api/fs/write/rollback", p.handleFsWriteRollback)
	mux.HandleFunc("/api/fs/rename", p.handleFsRename)
	mux.HandleFunc("/api/fs/remove", p.handleFsRemove)
	mux.HandleFunc("/api/fs/restore", p.handleFsRestore)
	mux.HandleFunc("/api/fs/upload", p.handleFsUpload)
	mux.HandleFunc("/api/fs/download", p.handleFsDownload)
	mux.HandleFunc("/api/task/start", p.requireAuth(p.handleTaskStart))
	mux.HandleFunc("/api/task/status", p.requireAuth(p.handleTaskStatus))
	mux.HandleFunc("/api/task/log", p.requireAuth(p.handleTaskLog))
	// P5：受控 PTY 终端（写走三重门，读走 requireAuth）
	mux.HandleFunc("/api/pty/open", p.handlePTYOpen)
	mux.HandleFunc("/api/pty/input", p.handlePTYInput)
	mux.HandleFunc("/api/pty/close", p.handlePTYClose)
	mux.HandleFunc("/api/pty/status", p.requireAuth(p.handlePTYStatus))
	mux.HandleFunc("/api/pty/list", p.requireAuth(p.handlePTYList))
	// 切片 A：AI 助手（写走三重门，读走 requireAuth）
	mux.HandleFunc("/api/ai/chat", p.handleAIChat)
	mux.HandleFunc("/api/ai/capability", p.requireAuth(p.handleAICapability))
	mux.HandleFunc("/", p.handleIndex)

	srv := &http.Server{Addr: *addr, Handler: p.securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("ocp-panel 监听 %s（R4：内网入口），agent=%s", *addr, *sock)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func dirOf(p string) string {
	i := len(p)
	for i > 0 && p[i-1] != '/' {
		i--
	}
	if i == 0 {
		return "."
	}
	return p[:i]
}

func readPasswordFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("管理员密码路径必须是普通文件，不能是符号链接或特殊文件")
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", errors.New("管理员密码文件必须仅对服务账户可读")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimRight(string(data), "\r\n")
	if len(trimmed) == 0 {
		return "", errors.New("管理员密码文件为空")
	}
	return trimmed, nil
}

// ---------- 认证（R4：服务端 Session cookie + CSRF 随机 + 登录限速） ----------

type session struct {
	token   string
	csrf    string
	created time.Time
}

var (
	sessions = map[string]session{}
	sessMu   sync.Mutex
)

const (
	sessionTTL  = 12 * time.Hour
	maxSessions = 4096
)

// pruneSessionsLocked also makes every auth lookup an opportunity to reclaim
// expired entries. The caller must hold sessMu.
func pruneSessionsLocked(now time.Time) {
	for token, s := range sessions {
		if !now.Before(s.created.Add(sessionTTL)) {
			delete(sessions, token)
		}
	}
}

func addSession(token string, s session, now time.Time) {
	sessMu.Lock()
	defer sessMu.Unlock()
	pruneSessionsLocked(now)
	if len(sessions) >= maxSessions {
		oldestToken := ""
		var oldest time.Time
		for candidate, current := range sessions {
			if oldestToken == "" || current.created.Before(oldest) {
				oldestToken, oldest = candidate, current.created
			}
		}
		delete(sessions, oldestToken)
	}
	sessions[token] = s
}

func lookupSession(token string, now time.Time) (session, bool) {
	sessMu.Lock()
	defer sessMu.Unlock()
	pruneSessionsLocked(now)
	s, ok := sessions[token]
	return s, ok
}

func deleteSession(token string) {
	sessMu.Lock()
	delete(sessions, token)
	sessMu.Unlock()
}

func (p *panel) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteIP, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	remoteIP = normalizeIP(remoteIP)
	if _, trusted := p.trustedProxyIPs[remoteIP]; trusted {
		if forwarded, parseErr := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); parseErr == nil {
			return normalizeIP(forwarded).String()
		}
	}
	return remoteIP.String()
}

func normalizeIP(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

func parseTrustedProxyIPs(raw string) (map[netip.Addr]struct{}, error) {
	ips := make(map[netip.Addr]struct{})
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ips, nil
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("可信反向代理地址列表包含空项")
		}
		ip, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("可信反向代理地址必须是单个 IP: %q", item)
		}
		ips[normalizeIP(ip)] = struct{}{}
	}
	return ips, nil
}

func loadTrustedProxyIPsFile(path string) (map[netip.Addr]struct{}, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect trusted proxy file: %w", err)
	}
	if info.Size() > 4096 {
		return nil, errors.New("trusted proxy file exceeds 4096 bytes")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("trusted proxy file must be a regular file not writable by group or others")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted proxy file: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return nil, errors.New("trusted proxy file must contain at least one exact IP address")
	}
	if len(fields) > 64 {
		return nil, errors.New("trusted proxy file exceeds 64 IP entries")
	}
	ips := make(map[netip.Addr]struct{})
	for _, item := range fields {
		parsed, err := parseTrustedProxyIPs(item)
		if err != nil {
			return nil, err
		}
		for ip := range parsed {
			ips[ip] = struct{}{}
		}
	}
	return ips, nil
}

func randomToken(byteLength int) (string, error) {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (p *panel) sameOriginHost(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	requestURL := &url.URL{Scheme: p.requestScheme(r), Host: r.Host}
	return strings.EqualFold(u.Scheme, requestURL.Scheme) && strings.EqualFold(u.Hostname(), requestURL.Hostname()) && effectivePort(u) == effectivePort(requestURL)
}

func (p *panel) isTrustedProxy(r *http.Request) bool {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	peer, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	_, ok := p.trustedProxyIPs[normalizeIP(peer)]
	return ok
}

func (p *panel) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p.isTrustedProxy(r) {
		forwardedProto := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("X-Forwarded-Proto"), ",", 2)[0]))
		if forwardedProto == "http" || forwardedProto == "https" {
			return forwardedProto
		}
	}
	return "http"
}

func (p *panel) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		if p.requestScheme(r) == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

const (
	loginFailureLimit  = 10
	maxTrackedLoginIPs = 4096
	loginFailureWindow = 15 * time.Minute
)

func (p *panel) loginNow() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *panel) recordAuth(r *http.Request, eventType, outcome, reason string) error {
	if p.authAudit == nil { // Only test fixtures may omit the durable writer; main requires it at startup.
		return nil
	}
	return p.authAudit.Record(authaudit.Event{
		At:       p.loginNow().UTC(),
		Type:     eventType,
		Outcome:  outcome,
		Reason:   reason,
		ClientIP: p.clientIP(r),
		Method:   r.Method,
	})
}

func (p *panel) rejectAuth(w http.ResponseWriter, r *http.Request, eventType, reason string, status int, message string) {
	if err := p.recordAuth(r, eventType, authaudit.OutcomeRejected, reason); err != nil {
		log.Printf("认证审计写入失败: %v", err)
		http.Error(w, "认证审计暂不可用，请稍后重试", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, message, status)
}

// pruneLoginAttemptsLocked expires old windows and removes orphaned counters.
// The caller must hold p.mu.
func (p *panel) pruneLoginAttemptsLocked(now time.Time) {
	if p.attempts == nil {
		p.attempts = make(map[string]int)
	}
	if p.attemptWindow == nil {
		p.attemptWindow = make(map[string]time.Time)
	}
	for ip, started := range p.attemptWindow {
		if !now.Before(started.Add(loginFailureWindow)) {
			delete(p.attemptWindow, ip)
			delete(p.attempts, ip)
		}
	}
	for ip := range p.attempts {
		if _, ok := p.attemptWindow[ip]; !ok {
			delete(p.attempts, ip)
		}
	}
}

// startLoginWindowLocked evicts the oldest tracked window when the map is full.
// The caller must hold p.mu and must have pruned expired entries first.
func (p *panel) startLoginWindowLocked(ip string, now time.Time) {
	if _, ok := p.attemptWindow[ip]; ok {
		return
	}
	if len(p.attemptWindow) >= maxTrackedLoginIPs {
		oldestIP := ""
		var oldest time.Time
		for trackedIP, started := range p.attemptWindow {
			if oldestIP == "" || started.Before(oldest) {
				oldestIP, oldest = trackedIP, started
			}
		}
		delete(p.attemptWindow, oldestIP)
		delete(p.attempts, oldestIP)
	}
	p.attemptWindow[ip] = now
	p.attempts[ip] = 0
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "ocp_session", Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "ocp_csrf", Value: "", Path: "/", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func (p *panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	ip := p.clientIP(r)
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			p.rejectAuth(w, r, authaudit.TypeLogin, "request_too_large", http.StatusRequestEntityTooLarge, "请求内容过大")
		} else {
			p.rejectAuth(w, r, authaudit.TypeLogin, "invalid_json", http.StatusBadRequest, "登录请求格式无效")
		}
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			p.rejectAuth(w, r, authaudit.TypeLogin, "request_too_large", http.StatusRequestEntityTooLarge, "请求内容过大")
		} else {
			p.rejectAuth(w, r, authaudit.TypeLogin, "invalid_json", http.StatusBadRequest, "登录请求格式无效")
		}
		return
	}
	if in.Username == "" || in.Password == "" {
		p.rejectAuth(w, r, authaudit.TypeLogin, "credentials_missing", http.StatusBadRequest, "登录信息不完整")
		return
	}

	now := p.loginNow()
	p.mu.Lock()
	p.pruneLoginAttemptsLocked(now)
	fails := p.attempts[ip]
	if fails >= loginFailureLimit {
		p.mu.Unlock()
		p.rejectAuth(w, r, authaudit.TypeLogin, "rate_limited", http.StatusTooManyRequests, "15 分钟内尝试次数过多，请稍后重试")
		return
	}
	p.startLoginWindowLocked(ip, now)
	p.attempts[ip]++ // 在校验前保留额度，避免并发请求绕过阈值
	p.mu.Unlock()

	if subtle.ConstantTimeCompare([]byte(in.Username), []byte("admin")) != 1 ||
		subtle.ConstantTimeCompare([]byte(in.Password), []byte(p.password)) != 1 {
		p.rejectAuth(w, r, authaudit.TypeLogin, "bad_credentials", http.StatusUnauthorized, "账号或密码错误")
		return
	}

	// P9：TOTP 两步验证。启用后必须携带有效 code，否则拒绝（不降级）。
	if totpEnabled() && !verifyTOTP(in.TOTPCode) {
		p.rejectAuth(w, r, authaudit.TypeLogin, "totp_required", http.StatusUnauthorized, "需要 TOTP 验证码")
		return
	}

	p.mu.Lock()
	delete(p.attempts, ip)
	delete(p.attemptWindow, ip)
	p.mu.Unlock()

	token, err := randomToken(24)
	if err != nil {
		http.Error(w, "无法创建登录会话", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "无法创建登录会话", http.StatusInternalServerError)
		return
	}
	createdAt := p.loginNow()
	addSession(token, session{token: token, csrf: csrfToken, created: createdAt}, createdAt)
	if err := p.recordAuth(r, authaudit.TypeLogin, authaudit.OutcomeSuccess, "credentials_accepted"); err != nil {
		deleteSession(token)
		log.Printf("认证审计写入失败: %v", err)
		http.Error(w, "认证审计暂不可用，请稍后重试", http.StatusServiceUnavailable)
		return
	}

	// 会话 12 小时有效
	http.SetCookie(w, &http.Cookie{
		Name: "ocp_session", Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(12 * time.Hour.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "ocp_csrf", Value: csrfToken, Path: "/",
		Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(12 * time.Hour.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

func (p *panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !p.sameOriginHost(r) {
		p.rejectAuth(w, r, authaudit.TypeLogout, "origin_mismatch", http.StatusForbidden, "跨站请求已拒绝")
		return
	}
	c, err := r.Cookie("ocp_session")
	if err != nil {
		clearAuthCookies(w)
		p.rejectAuth(w, r, authaudit.TypeLogout, "session_missing", http.StatusUnauthorized, "未登录")
		return
	}

	s, ok := lookupSession(c.Value, p.loginNow())
	if !ok {
		clearAuthCookies(w)
		p.rejectAuth(w, r, authaudit.TypeLogout, "session_expired_or_unknown", http.StatusUnauthorized, "会话失效")
		return
	}
	csrfCookie, cookieErr := r.Cookie("ocp_csrf")
	csrfHeader := r.Header.Get("X-CSRF-Token")
	if cookieErr != nil || s.csrf == "" || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(s.csrf)) != 1 || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(s.csrf)) != 1 {
		p.rejectAuth(w, r, authaudit.TypeLogout, "csrf_failed", http.StatusForbidden, "安全校验失败，请刷新页面后重试")
		return
	}
	if err := p.recordAuth(r, authaudit.TypeLogout, authaudit.OutcomeSuccess, "logout_completed"); err != nil {
		log.Printf("认证审计写入失败: %v", err)
		http.Error(w, "认证审计暂不可用，请稍后重试", http.StatusServiceUnavailable)
		return
	}
	deleteSession(c.Value)

	clearAuthCookies(w)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

func (p *panel) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("ocp_session")
		if err != nil {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		if _, ok := lookupSession(c.Value, p.loginNow()); !ok {
			http.Error(w, "会话失效", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---------- 数据 API（全部实时过 agent，R1：不落库当真源） ----------

func (p *panel) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	info, err1 := p.clients.Call("system.info", nil)
	metrics, err2 := p.clients.Call("system.metrics", nil)
	writeJSON(w, map[string]any{"info": info, "metrics": metrics,
		"agent_errors": map[string]any{"system.info": errStr(err1), "system.metrics": errStr(err2)}})
}

func (p *panel) handleDocker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	summary, err1 := p.clients.Call("docker.summary", nil)
	containers, err2 := p.clients.Call("docker.containers", nil)
	writeJSON(w, map[string]any{"summary": summary, "containers": containers,
		"agent_errors": map[string]any{"docker.summary": errStr(err1), "docker.containers": errStr(err2)}})
}

func (p *panel) handleNginx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	// P3：返回增强发现（vhost + 证书到期 + proxy 标记 + nginx 容器事实）。
	data, err := p.clients.Call("nginx.sites.full", nil)
	writeJSON(w, map[string]any{"sites": data, "agent_error": errStr(err)})
}

// handleNginxSiteDetail returns one vhost config's real content (detail view).
// The file must be a discovered vhost path (validated agent-side).
func (p *panel) handleNginxSiteDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	file := strings.TrimSpace(r.URL.Query().Get("file"))
	if file == "" {
		writeJSON(w, map[string]any{"ok": false, "agent_error": "file is required"})
		return
	}
	data, err := p.clients.Call("nginx.site.detail", map[string]any{"file": file})
	writeJSON(w, map[string]any{"detail": data, "agent_error": errStr(err)})
}

func (p *panel) handleNet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("net.interfaces", nil)
	writeJSON(w, map[string]any{"interfaces": data, "agent_error": errStr(err)})
}

func (p *panel) handleProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := p.clients.Call("processes", map[string]any{"top": 20})
	writeJSON(w, map[string]any{"processes": data, "agent_error": errStr(err)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func (p *panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		log.Printf("前端未嵌入: %v", err)
		http.Error(w, "前端未嵌入", http.StatusServiceUnavailable)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		http.Error(w, "无法初始化安全页面", http.StatusInternalServerError)
		return
	}
	page := strings.ReplaceAll(string(b), "__OCP_CSP_NONCE__", nonce)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, page)
}
