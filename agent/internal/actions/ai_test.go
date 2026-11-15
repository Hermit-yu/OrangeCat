package actions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 测试用：临时切换 aiOn 状态。
func setAIForTest(on bool) func() {
	prev := aiOn
	aiOn = on
	return func() { aiOn = prev }
}

func TestAIChatDisabled(t *testing.T) {
	restore := setAIForTest(false)
	defer restore()
	_, err := AIChat(context.Background(), map[string]any{"message": "hi"})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("want disabled error, got %v", err)
	}
}

func TestAIChatRejectsUnknownParam(t *testing.T) {
	restore := setAIForTest(true)
	defer restore()
	_, err := AIChat(context.Background(), map[string]any{"message": "hi", "shell": "rm -rf"})
	if err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("want unknown param error, got %v", err)
	}
}

func TestAIChatRequiresKey(t *testing.T) {
	restore := setAIForTest(true)
	defer restore()
	t.Setenv(aiKeyEnv, "")
	t.Setenv(aiBaseURLEnv, "")
	t.Setenv(aiModelEnv, "")
	_, err := AIChat(context.Background(), map[string]any{"message": "hi"})
	if err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("want key error, got %v", err)
	}
}

func TestAIChatRoundTrip(t *testing.T) {
	restore := setAIForTest(true)
	defer restore()

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key-123" {
			t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("missing User-Agent (WAF)")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		gotBody = body
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好！我是真实 AI 助手。"}}]}`))
	}))
	defer srv.Close()

	t.Setenv(aiKeyEnv, "test-key-123")
	t.Setenv(aiBaseURLEnv, srv.URL)
	t.Setenv(aiModelEnv, "agnes-3.0-flash")

	res, err := AIChat(context.Background(), map[string]any{
		"message": "你好",
		"history": []any{
			map[string]any{"role": "user", "content": "第一问"},
			map[string]any{"role": "assistant", "content": "第一答"},
		},
	})
	if err != nil {
		t.Fatalf("AIChat: %v", err)
	}
	reply, _ := res["reply"].(string)
	if !strings.Contains(reply, "真实 AI 助手") {
		t.Fatalf("unexpected reply: %q", reply)
	}
	// 验证消息顺序：system 无 → history 2 条 → 当前 user
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d", len(msgs))
	}
	last := msgs[2].(map[string]any)
	if last["role"] != "user" || last["content"] != "你好" {
		t.Fatalf("bad last message: %v", last)
	}
}

func TestAIChatRejectsOverlongMessage(t *testing.T) {
	restore := setAIForTest(true)
	defer restore()
	t.Setenv(aiKeyEnv, "test-key")
	t.Setenv(aiBaseURLEnv, "https://example.com/v1")
	t.Setenv(aiModelEnv, "agnes-3.0-flash")
	long := strings.Repeat("x", aiMaxInputBytes+1)
	_, err := AIChat(context.Background(), map[string]any{"message": long})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("want too long error, got %v", err)
	}
}

func TestAIChatUpstreamError(t *testing.T) {
	restore := setAIForTest(true)
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer srv.Close()
	t.Setenv(aiKeyEnv, "bad-key")
	t.Setenv(aiBaseURLEnv, srv.URL)
	t.Setenv(aiModelEnv, "agnes-3.0-flash")
	_, err := AIChat(context.Background(), map[string]any{"message": "hi"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("want HTTP 401 error, got %v", err)
	}
}

func TestParseAIHistoryBounds(t *testing.T) {
	// 超过条数上限应裁剪
	var arr []any
	for i := 0; i < 50; i++ {
		arr = append(arr, map[string]any{"role": "user", "content": "msg"})
	}
	got, err := parseAIHistory(arr)
	if err != nil {
		t.Fatalf("parseAIHistory: %v", err)
	}
	if len(got) > aiMaxHistoryItems {
		t.Fatalf("history not bounded: %d", len(got))
	}
	// 非法角色应跳过
	got, err = parseAIHistory([]any{
		map[string]any{"role": "system", "content": "x"},
		map[string]any{"role": "user", "content": "ok"},
	})
	if err != nil || len(got) != 1 || got[0].Content != "ok" {
		t.Fatalf("bad role filtering: %v %v", got, err)
	}
}
