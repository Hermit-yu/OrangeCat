package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ── AI 助手联网工具（web_search / fetch_url）──
// 模型通过 OpenAI function calling 主动调用；agent 在服务端真实执行，
// 把结果作为 tool 角色消息喂回模型，模型再综合回答。
//
// 安全基线：
//   - 不执行任何 shell、不访问本地文件系统。
//   - fetch_url 仅允许 http/https，且拒绝重定向/直连到私有或回环地址（防 SSRF）。
//   - 全部响应体按 aiFetchMaxBytes 截断，单次联网调用受 aiToolCallTimeout 约束。
//   - 工具参数固定字段，不接受任意结构。

const (
	aiSearchTimeout    = 12 * time.Second
	aiFetchTimeout     = 15 * time.Second
	aiToolCallTimeout  = 25 * time.Second
	aiFetchMaxBytes    = 200 << 10 // 单次抓取响应体上限 200 KiB
	aiToolRounds       = 4         // 单次对话最多工具往返轮数
	aiSearchResultsMax = 6
)

// aiWebToolDefs is the OpenAI function-calling tool schema advertised to the model.
var aiWebToolDefs = []map[string]any{
	{
		"type": "function",
		"function": map[string]any{
			"name":        "web_search",
			"description": "搜索公开网页。适合时效性问题、事实核查、需要最新信息时使用。返回若干条标题+摘要+链接。",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "搜索关键词"},
				},
				"required": []string{"query"},
			},
		},
	},
	{
		"type": "function",
		"function": map[string]any{
			"name":        "fetch_url",
			"description": "抓取一个公开网页的正文纯文本。用于读取 web_search 结果里某个链接的详细内容。",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "完整的 http(s) 链接"},
				},
				"required": []string{"url"},
			},
		},
	},
}

// aiWebHTTPClient blocks redirects to private/loopback targets (SSRF guard).
var aiWebHTTPClient = &http.Client{
	Timeout: aiFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		host := req.URL.Hostname()
		if isPrivateOrLoopbackHost(host) {
			return fmt.Errorf("refusing to follow redirect to private host %q", host)
		}
		return nil
	},
}

// aiSearchResult is one parsed search hit.
type aiSearchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

// aiWebSearch runs one public web search and returns compact JSON results.
func aiWebSearch(ctx context.Context, query string) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", errors.New("query is required")
	}
	if len(query) > 300 {
		query = query[:300]
	}
	client := &http.Client{Timeout: aiSearchTimeout}
	endpoint := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build search request: %w", err)
	}
	req.Header.Set("User-Agent", aiUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("search backend unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, aiFetchMaxBytes))
	if err != nil {
		return "", fmt.Errorf("read search response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("search backend returned HTTP %d", resp.StatusCode)
	}
	results := parseDDGResults(string(body))
	if len(results) == 0 {
		return `{"results":[],"note":"no results"}`, nil
	}
	payload, err := json.Marshal(map[string]any{"results": results})
	if err != nil {
		return "", fmt.Errorf("marshal search results: %w", err)
	}
	return string(payload), nil
}

var (
	ddgLinkRe   = regexp.MustCompile(`class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>`)
	ddgSnipRe   = regexp.MustCompile(`class="result__snippet"[^>]*>(.*?)</(?:a|div|td)>`)
	ddgURLDecRe = regexp.MustCompile(`uddg=([^&]+)`)
)

// parseDDGResults extracts title/url/snippet triples from DDG HTML results.
func parseDDGResults(body string) []aiSearchResult {
	linkBlocks := ddgLinkRe.FindAllStringSubmatch(body, aiSearchResultsMax*2)
	snippets := ddgSnipRe.FindAllStringSubmatch(body, aiSearchResultsMax*2)
	out := make([]aiSearchResult, 0, len(linkBlocks))
	for i, m := range linkBlocks {
		rawURL := html.UnescapeString(m[1])
		title := stripHTMLTags(m[2])
		finalURL := decodeDDGRedirect(rawURL)
		if title == "" || finalURL == "" || !strings.HasPrefix(finalURL, "http") {
			continue
		}
		snip := ""
		if i < len(snippets) {
			snip = stripHTMLTags(snippets[i][1])
		}
		out = append(out, aiSearchResult{
			Title:   truncate(title, 200),
			URL:     finalURL,
			Snippet: truncate(snip, 300),
		})
		if len(out) >= aiSearchResultsMax {
			break
		}
	}
	return out
}

// decodeDDGRedirect unwraps DuckDuckGo's /l/?uddg=... redirect wrapper.
func decodeDDGRedirect(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Host != "" && strings.Contains(u.Path, "/l/") {
		if enc := ddgURLDecRe.FindStringSubmatch(u.RawQuery); len(enc) > 1 {
			if dec, err := url.QueryUnescape(enc[1]); err == nil && dec != "" {
				return dec
			}
		}
	}
	return raw
}

// aiFetchURL downloads one public page and returns its stripped plain text.
func aiFetchURL(ctx context.Context, rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("only http and https are allowed")
	}
	if isPrivateOrLoopbackHost(u.Hostname()) {
		return "", errors.New("private and loopback hosts are not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build fetch request: %w", err)
	}
	req.Header.Set("User-Agent", aiUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := aiWebHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, aiFetchMaxBytes))
	if err != nil {
		return "", fmt.Errorf("read fetch response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch returned HTTP %d", resp.StatusCode)
	}
	text := stripHTMLTags(string(body))
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return "", errors.New("page returned no readable text")
	}
	payload, err := json.Marshal(map[string]any{
		"url":   u.String(),
		"title": truncate(extractHTMLTitle(string(body)), 200),
		"text":  truncate(text, 6000),
	})
	if err != nil {
		return "", fmt.Errorf("marshal fetch result: %w", err)
	}
	return string(payload), nil
}

var (
	htmlScriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	htmlStyleRe  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	htmlNoscrRe  = regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`)
	htmlTagRe    = regexp.MustCompile(`(?s)<[^>]+>`)
	htmlTitleRe  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// stripHTMLTags removes scripts/styles and all tags, unescaping entities.
func stripHTMLTags(s string) string {
	s = htmlScriptRe.ReplaceAllString(s, " ")
	s = htmlStyleRe.ReplaceAllString(s, " ")
	s = htmlNoscrRe.ReplaceAllString(s, " ")
	s = htmlTagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

// extractHTMLTitle returns the <title> text if present.
func extractHTMLTitle(body string) string {
	m := htmlTitleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return stripHTMLTags(m[1])
}

// isPrivateOrLoopbackHost reports whether host resolves to a non-public address.
func isPrivateOrLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if net.ParseIP(host) != nil {
		return !isPublicIP(net.ParseIP(host))
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// 解析失败时保守放行（外网域名偶发解析抖动），实际请求会自然失败。
		return false
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return true
		}
	}
	return false
}

// isPublicIP reports whether ip is a globally routable address.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}
	return true
}

// aiRunWebTool dispatches one tool call from the model and returns its result
// (as JSON string for the tool role message).
func aiRunWebTool(ctx context.Context, name, argsJSON string) string {
	if ctx.Err() != nil {
		return `{"error":"context cancelled"}`
	}
	var args map[string]any
	_ = json.Unmarshal([]byte(argsJSON), &args)
	switch name {
	case "web_search":
		q, _ := args["query"].(string)
		res, err := aiWebSearch(ctx, q)
		if err != nil {
			return `{"error":` + mustJSONString(err.Error()) + `}`
		}
		return res
	case "fetch_url":
		u, _ := args["url"].(string)
		res, err := aiFetchURL(ctx, u)
		if err != nil {
			return `{"error":` + mustJSONString(err.Error()) + `}`
		}
		return res
	default:
		return `{"error":"unknown tool"}`
	}
}

// mustJSONString encodes s as a JSON string value (never fails for plain text).
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
