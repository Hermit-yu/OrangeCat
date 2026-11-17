package actions

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestStripHTMLTags(t *testing.T) {
	in := `<html><head><title>测试标题</title><style>.x{color:red}</style></head>
	<body><script>alert(1)</script><p>正文   内容</p><a href="#">链接</a></body></html>`
	out := stripHTMLTags(in)
	if strings.Contains(out, "script") || strings.Contains(out, ".x") || strings.Contains(out, "<") {
		t.Fatalf("stripHTMLTags left markup/script: %q", out)
	}
	if !strings.Contains(out, "测试标题") || !strings.Contains(out, "正文 内容") {
		t.Fatalf("stripHTMLTags dropped visible text: %q", out)
	}
}

func TestExtractHTMLTitle(t *testing.T) {
	if got := extractHTMLTitle("<html><title>  Hello &amp; World </title></html>"); got != "Hello & World" {
		t.Fatalf("extractHTMLTitle = %q, want %q", got, "Hello & World")
	}
	if got := extractHTMLTitle("<html><head></head></html>"); got != "" {
		t.Fatalf("extractHTMLTitle(no title) = %q, want empty", got)
	}
}

func TestDecodeDDGRedirect(t *testing.T) {
	// DuckDuckGo wraps target URLs in /l/?uddg=<encoded>.
	wrapped := "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc"
	if got := decodeDDGRedirect(wrapped); got != "https://example.com/page" {
		t.Fatalf("decodeDDGRedirect(wrapped) = %q", got)
	}
	direct := "https://example.com/plain"
	if got := decodeDDGRedirect(direct); got != direct {
		t.Fatalf("decodeDDGRedirect(direct) = %q", got)
	}
}

func TestParseDDGResults(t *testing.T) {
	html := `
	<div class="result">
	  <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fone.example%2Fa">标题一</a>
	  <div class="result__snippet">摘要一 内容</div>
	</div>
	<div class="result">
	  <a class="result__a" href="https://two.example/b">标题二</a>
	  <div class="result__snippet">摘要二</div>
	</div>`
	res := parseDDGResults(html)
	if len(res) != 2 {
		t.Fatalf("parseDDGResults len = %d, want 2", len(res))
	}
	if res[0].URL != "https://one.example/a" || res[0].Title != "标题一" || res[0].Snippet != "摘要一 内容" {
		t.Fatalf("parseDDGResults[0] = %+v", res[0])
	}
	if res[1].URL != "https://two.example/b" {
		t.Fatalf("parseDDGResults[1].URL = %q", res[1].URL)
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
		{"::1", false},
	}
	for _, c := range cases {
		if got := isPublicIP(net.ParseIP(c.ip)); got != c.public {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.public)
		}
	}
}

func TestIsPrivateOrLoopbackHost(t *testing.T) {
	if !isPrivateOrLoopbackHost("localhost") {
		t.Error("localhost should be private")
	}
	if !isPrivateOrLoopbackHost("127.0.0.1") {
		t.Error("127.0.0.1 should be private")
	}
	if !isPrivateOrLoopbackHost("192.168.1.1") {
		t.Error("192.168.1.1 should be private")
	}
}

func TestAIWebToolUnknown(t *testing.T) {
	res := aiRunWebTool(context.Background(), "bogus_tool", "{}")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(res), &parsed); err != nil {
		t.Fatalf("aiRunWebTool(unknown) not JSON: %v", err)
	}
	if parsed["error"] != "unknown tool" {
		t.Fatalf("aiRunWebTool(unknown) = %v", parsed)
	}
}

func TestAIWebSearchEmptyQuery(t *testing.T) {
	res := aiRunWebTool(context.Background(), "web_search", `{"query":"  "}`)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(res), &parsed); err != nil {
		t.Fatalf("web_search(empty) not JSON: %v", err)
	}
	if _, ok := parsed["error"]; !ok {
		t.Fatalf("web_search(empty query) should return error, got %v", parsed)
	}
}

func TestAIFetchURLRejectsPrivate(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1/x", "http://localhost/x", "ftp://example.com/x"} {
		res := aiRunWebTool(context.Background(), "fetch_url", `{"url":"`+u+`"}`)
		var parsed map[string]any
		if err := json.Unmarshal([]byte(res), &parsed); err != nil {
			t.Fatalf("fetch_url(%s) not JSON: %v", u, err)
		}
		if _, ok := parsed["error"]; !ok {
			t.Fatalf("fetch_url(%s) should return error, got %v", u, parsed)
		}
	}
}

func TestAIWebToolDefsShape(t *testing.T) {
	if len(aiWebToolDefs) != 2 {
		t.Fatalf("aiWebToolDefs len = %d, want 2", len(aiWebToolDefs))
	}
	names := map[string]bool{}
	for _, def := range aiWebToolDefs {
		fn, ok := def["function"].(map[string]any)
		if !ok {
			t.Fatalf("tool def missing function map: %+v", def)
		}
		name, _ := fn["name"].(string)
		names[name] = true
	}
	if !names["web_search"] || !names["fetch_url"] {
		t.Fatalf("aiWebToolDefs missing expected tools: %v", names)
	}
}
