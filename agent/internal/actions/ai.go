package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── AI 助手（切片 A：真实绑定 agnes-ai.com OpenAI 兼容端点） ──
// 能力默认关闭：OCP_AGENT_AI_ENABLED=1 才启用（独立开关，同 PTY 安全基线）。
// key/base_url/model 从环境变量读取，不写死、不落日志。

const (
	aiMaxInputBytes   = 32 << 10  // 单次用户输入上限 32 KiB
	aiMaxOutputBytes  = 128 << 10 // 单次响应上限 128 KiB
	aiTimeout         = 60 * time.Second
	aiMaxMessages     = 40       // 单次请求消息条数上限
	aiMaxHistoryChars = 64 << 10 // 上下文历史总量上限 64 KiB
	aiMaxHistoryItems = 20       // 携带的历史消息条数上限
	aiKeyEnv          = "OCP_AGENT_AI_KEY"
	aiBaseURLEnv      = "OCP_AGENT_AI_BASE_URL"
	aiModelEnv        = "OCP_AGENT_AI_MODEL"
	aiDefaultBaseURL  = "https://apihub.agnes-ai.com/v1"
	aiDefaultModel    = "agnes-3.0-flash"
	aiUserAgent       = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	aiWebEnabled      = true // 联网工具（web_search/fetch_url）总开关
)

var (
	aiOnce sync.Once
	aiOn   bool
)

// AIEnabled reports whether the AI capability is enabled (default false).
func AIEnabled() bool { return aiOn }

// EnableAI turns on the AI capability. Called once at startup from main.go
// when OCP_AGENT_AI_ENABLED=1. Idempotent.
func EnableAI() { aiOnce.Do(func() { aiOn = true }) }

// aiConfig holds the resolved endpoint config for one call.
type aiConfig struct {
	Key     string
	BaseURL string
	Model   string
}

func loadAIConfig() (aiConfig, error) {
	key := os.Getenv(aiKeyEnv)
	if key == "" {
		return aiConfig{}, errors.New("AI capability enabled but OCP_AGENT_AI_KEY is not set")
	}
	base := os.Getenv(aiBaseURLEnv)
	if base == "" {
		base = aiDefaultBaseURL
	}
	model := os.Getenv(aiModelEnv)
	if model == "" {
		model = aiDefaultModel
	}
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" || (!strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://")) {
		return aiConfig{}, errors.New("invalid OCP_AGENT_AI_BASE_URL")
	}
	return aiConfig{Key: key, BaseURL: base, Model: model}, nil
}

// chatCompletion calls the LLM once with the given message list and returns the
// raw response message (role/content/tool_calls). Non-streaming.
func chatCompletion(ctx context.Context, cfg aiConfig, model string, messages []map[string]any, tools []map[string]any) (aiLLMMessage, string, error) {
	body := map[string]any{
		"model":       model,
		"messages":    messages,
		"temperature": 0.3,
		"max_tokens":  4096,
		"stream":      false,
	}
	if len(tools) > 0 {
		body["tools"] = tools
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return aiLLMMessage{}, "", fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return aiLLMMessage{}, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Key)
	req.Header.Set("User-Agent", aiUserAgent) // apihub WAF 要求浏览器 UA

	client := &http.Client{Timeout: aiTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return aiLLMMessage{}, "", fmt.Errorf("LLM endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, aiMaxOutputBytes))
	if err != nil {
		return aiLLMMessage{}, string(raw), fmt.Errorf("read LLM response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return aiLLMMessage{}, string(raw), fmt.Errorf("LLM endpoint returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message aiLLMMessage `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return aiLLMMessage{}, string(raw), fmt.Errorf("parse LLM response: %w", err)
	}
	if out.Error != nil {
		return aiLLMMessage{}, string(raw), fmt.Errorf("LLM error: %s", truncate(out.Error.Message, 200))
	}
	if len(out.Choices) == 0 {
		return aiLLMMessage{}, string(raw), errors.New("LLM returned no choices")
	}
	return out.Choices[0].Message, string(raw), nil
}

// aiLLMMessage mirrors an OpenAI chat message, including optional tool calls.
type aiLLMMessage struct {
	Role       string            `json:"role"`
	Content    string            `json:"content"`
	ToolCalls []aiToolCall      `json:"tool_calls,omitempty"`
}

type aiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// AIChat sends one user message to the configured LLM endpoint and returns the
// assistant reply. Params: {"message": string, "history": [{role,content}...],
// "model": optional override, "system": optional system prompt}.
//
// When web tools are enabled the model may request web_search/fetch_url tool
// calls; those run server-side and results are fed back for up to
// aiToolRounds rounds before the final reply.
//
// Security posture: no shell, no filesystem access, no arbitrary params; only
// the fixed message/history/model/system fields are accepted, all bounded.
func AIChat(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		switch key {
		case "message", "history", "model", "system":
		default:
			return nil, fmt.Errorf("ai.chat does not accept the %q parameter", key)
		}
	}
	if !aiOn {
		return nil, errors.New("AI capability is disabled")
	}
	cfg, err := loadAIConfig()
	if err != nil {
		return nil, err
	}
	message, _ := p["message"].(string)
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, errors.New("message is required")
	}
	if len(message) > aiMaxInputBytes {
		return nil, errors.New("message too long")
	}
	model := cfg.Model
	if m, ok := p["model"].(string); ok && strings.TrimSpace(m) != "" {
		model = strings.TrimSpace(m)
	}
	system, _ := p["system"].(string)
	if len(system) > aiMaxInputBytes {
		return nil, errors.New("system prompt too long")
	}
	history, err := parseAIHistory(p["history"])
	if err != nil {
		return nil, err
	}

	// Build OpenAI-compatible request body (loosely typed to allow tool msgs).
	messages := make([]map[string]any, 0, len(history)+2+aiToolRounds*2)
	if system != "" {
		messages = append(messages, map[string]any{"role": "system", "content": system})
	}
	for _, h := range history {
		messages = append(messages, map[string]any{"role": h.Role, "content": h.Content})
	}
	messages = append(messages, map[string]any{"role": "user", "content": message})

	tools := aiWebToolDefs
	usedWeb := false

	var reply string
	for round := 0; round <= aiToolRounds; round++ {
		msg, _, err := chatCompletion(ctx, cfg, model, messages, tools)
		if err != nil {
			return nil, err
		}
		if len(msg.ToolCalls) == 0 || !aiWebEnabled {
			reply = strings.TrimSpace(msg.Content)
			break
		}
		usedWeb = true
		// Append the assistant tool-call message verbatim so the model sees it.
		messages = append(messages, map[string]any{
			"role":       msg.Role,
			"content":    msg.Content,
			"tool_calls": msg.ToolCalls,
		})
		for _, tc := range msg.ToolCalls {
			var res string
			func() {
				toolCtx, cancel := context.WithTimeout(ctx, aiToolCallTimeout)
				defer cancel()
				res = aiRunWebTool(toolCtx, tc.Function.Name, tc.Function.Arguments)
			}()
			messages = append(messages, map[string]any{
				"role":         "tool",
				"tool_call_id": tc.ID,
				"content":      res,
			})
		}
		if round == aiToolRounds {
			// Exhausted rounds: force a final text answer without tools.
			forced := make([]map[string]any, len(messages))
			copy(forced, messages)
			finalMsg, _, err := chatCompletion(ctx, cfg, model, forced, nil)
			if err != nil {
				return nil, err
			}
			reply = strings.TrimSpace(finalMsg.Content)
		}
	}
	if strings.TrimSpace(reply) == "" {
		return nil, errors.New("LLM returned no content")
	}
	return map[string]any{
		"reply":      reply,
		"model":      model,
		"used_web":   usedWeb,
		"usage":      map[string]any{"reply_chars": len(reply)},
		"truncated":  false,
		"capability": "ai.chat",
	}, nil
}

// AIStatus reports whether the AI capability is enabled (no params).
func AIStatus(ctx context.Context, p map[string]any) (map[string]any, error) {
	for key := range p {
		return nil, fmt.Errorf("ai.status does not accept the %q parameter", key)
	}
	cfg, _ := loadAIConfig()
	return map[string]any{
		"enabled": aiOn,
		"model":   cfg.Model,
		"base":    cfg.BaseURL,
	}, nil
}

type aiHistoryMsg struct {
	Role    string
	Content string
}

func parseAIHistory(v any) ([]aiHistoryMsg, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("history must be an array")
	}
	if len(arr) > aiMaxHistoryItems {
		arr = arr[len(arr)-aiMaxHistoryItems:]
	}
	var out []aiHistoryMsg
	total := 0
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		content, _ := m["content"].(string)
		if role != "user" && role != "assistant" {
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			continue
		}
		total += len(content)
		if total > aiMaxHistoryChars {
			break
		}
		out = append(out, aiHistoryMsg{Role: role, Content: content})
	}
	if len(out) > aiMaxHistoryItems {
		out = out[len(out)-aiMaxHistoryItems:]
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}