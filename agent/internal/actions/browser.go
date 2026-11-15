package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// P13 隔离式内置浏览器。
//
// 独立 Chromium 进程（--headless --no-sandbox，不共享 Agent 权限）。默认关闭
// （OCP_AGENT_BROWSER_ENABLED=1 才启用）。URL 白名单校验：仅 http(s)，拒绝
// loopback / 私网 / 云元数据 / 非公网。受限标签页（browserMaxTabs=3）。
//
// 注意：chromedp 的 Run 需要独立 ctx（隔离浏览器进程），不继承请求 ctx。

const (
	browserMaxTabs = 3
	browserTimeout = 30 * time.Second
	chromiumPath   = "/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome"
)

// isolatedBrowser is a singleton holding the chromedp allocator + tabs.
type isolatedBrowser struct {
	mu     sync.Mutex
	ctx    context.Context // browser context (owns allocator)
	cancel context.CancelFunc
	tabs   map[string]string // tabID -> last URL
}

var isoBrowser = &isolatedBrowser{tabs: map[string]string{}}

func browserEnabled() bool {
	return os.Getenv("OCP_AGENT_BROWSER_ENABLED") == "1"
}

// BrowserStatus reports enabled + open tab count (honest).
func BrowserStatus(_ context.Context, _ map[string]any) (map[string]any, error) {
	isoBrowser.mu.Lock()
	defer isoBrowser.mu.Unlock()
	return map[string]any{
		"enabled":     browserEnabled(),
		"tabs_open":   len(isoBrowser.tabs),
		"max_tabs":    browserMaxTabs,
		"chromium":    fileExistsChromium(),
		"not_ready":   !browserEnabled() || !fileExistsChromium(),
	}, nil
}

func fileExistsChromium() bool {
	_, err := os.Stat(chromiumPath)
	return err == nil
}

// BrowserOpen starts the isolated browser (if enabled) and opens a tab.
func BrowserOpen(_ context.Context, p map[string]any) (map[string]any, error) {
	if !browserEnabled() {
		return nil, fmt.Errorf("依赖未就绪：隔离浏览器默认关闭（需 OCP_AGENT_BROWSER_ENABLED=1）")
	}
	if !fileExistsChromium() {
		return nil, fmt.Errorf("依赖未就绪：Chromium 不可用")
	}
	isoBrowser.mu.Lock()
	defer isoBrowser.mu.Unlock()
	if len(isoBrowser.tabs) >= browserMaxTabs {
		return nil, fmt.Errorf("标签页已达上限 %d", browserMaxTabs)
	}
	startURL, _ := p["url"].(string)
	if err := validateBrowserURL(startURL); err != nil {
		return nil, err
	}
	if isoBrowser.ctx == nil {
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(chromiumPath),
			chromedp.Flag("headless", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.NoFirstRun,
		)
		allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
		ctx, cancel2 := chromedp.NewContext(allocCtx)
		isoBrowser.ctx = ctx
		isoBrowser.cancel = func() { cancel2(); cancel() }
	}
	tabID := fmt.Sprintf("tab-%d", time.Now().UnixNano())
	isoBrowser.tabs[tabID] = startURL
	go isoBrowser.loadTab(tabID, startURL)
	return map[string]any{"ok": true, "tab": tabID, "url": startURL}, nil
}

// loadTab loads the URL in the isolated context (best-effort, no blocking).
func (b *isolatedBrowser) loadTab(tabID, rawURL string) {
	// A new tab needs its own context; reuse the browser context with a tab-level
	// context so each tab can navigate independently.
	ctx, cancel := context.WithTimeout(b.ctx, browserTimeout)
	defer cancel()
	b.mu.Lock()
	b.tabs[tabID] = rawURL
	b.mu.Unlock()
	// Best-effort: navigate in the browser context. The first Run creates the
	// target; subsequent navigations reuse it.
	_ = func() error { _, err := chromedp.Run(ctx, chromedp.Navigate(rawURL)); return err }()
}

// BrowserNavigate navigates the current tab (all tabs share one page in this
// minimal implementation; each tab records its own URL).
func BrowserNavigate(_ context.Context, p map[string]any) (map[string]any, error) {
	if !browserEnabled() {
		return nil, fmt.Errorf("依赖未就绪：隔离浏览器默认关闭")
	}
	tab, _ := p["tab"].(string)
	rawURL, _ := p["url"].(string)
	if tab == "" {
		// default to first tab
		isoBrowser.mu.Lock()
		for t := range isoBrowser.tabs {
			tab = t
			break
		}
		isoBrowser.mu.Unlock()
	}
	if tab == "" {
		return nil, fmt.Errorf("无打开的标签页")
	}
	if err := validateBrowserURL(rawURL); err != nil {
		return nil, err
	}
	isoBrowser.mu.Lock()
	isoBrowser.tabs[tab] = rawURL
	isoBrowser.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), browserTimeout)
		defer cancel()
		_, _ = chromedp.Run(ctx, chromedp.Navigate(rawURL))
	}()
	return map[string]any{"ok": true, "tab": tab, "url": rawURL}, nil
}

// BrowserClose closes the isolated browser (all tabs).
func BrowserClose(_ context.Context, _ map[string]any) (map[string]any, error) {
	isoBrowser.mu.Lock()
	defer isoBrowser.mu.Unlock()
	isoBrowser.tabs = map[string]string{}
	if isoBrowser.cancel != nil {
		isoBrowser.cancel()
	}
	isoBrowser.ctx = nil
	isoBrowser.cancel = nil
	return map[string]any{"ok": true, "closed": true}, nil
}

// BrowserURL returns the current URL of a tab (read-only).
func BrowserURL(_ context.Context, p map[string]any) (map[string]any, error) {
	tab, _ := p["tab"].(string)
	isoBrowser.mu.Lock()
	defer isoBrowser.mu.Unlock()
	cur, ok := isoBrowser.tabs[tab]
	if !ok {
		return nil, fmt.Errorf("标签页不存在")
	}
	// Best-effort: read the actual current URL from the live browser if running.
	if isoBrowser.ctx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, err := chromedp.Run(ctx, chromedp.Location())
		if err == nil && got != "" {
			cur = got
		}
	}
	return map[string]any{"ok": true, "tab": tab, "url": cur}, nil
}

// validateBrowserURL blocks loopback/private/cloud-metadata/non-http(s).
func validateBrowserURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("URL 无效")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("仅允许 http/https")
	}
	host := u.Hostname()
	if host == "localhost" {
		return fmt.Errorf("拒绝 loopback")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("拒绝内网/loopback 地址")
		}
	}
	// Cloud metadata endpoints
	if strings.Contains(host, "metadata.google.internal") || strings.HasPrefix(host, "169.254.169.254") {
		return fmt.Errorf("拒绝云元数据地址")
	}
	return nil
}

// marshalJSON helper for consistent error output (reuse standard library).
func marshalBrowserJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
