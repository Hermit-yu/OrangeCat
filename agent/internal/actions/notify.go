package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// P7：Telegram 通知能力。
//
// 凭据从环境变量注入（OCP_AGENT_NOTIFY_TOKEN / OCP_AGENT_NOTIFY_CHAT_ID），
// 不写死、不落日志。没有配置 token 时所有动作明确返回"依赖未就绪"，
// 不编造发送成功。
//
// 启用纪律（P7 验收）：notify.test 必须先真实抵达指定 chat_id 才视为已
// 配置；notify.alert 在未配置时拒绝触发。

const notifyTimeout = 15 * time.Second

// notifyConfig holds the Telegram bot credentials from the environment.
// token/chatID are read once per call (env could change between restarts).
func notifyConfig() (token, chatID string, ok bool) {
	token = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_TOKEN"))
	chatID = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_CHAT_ID"))
	return token, chatID, token != "" && chatID != ""
}

// sendTelegram posts a message to the Telegram bot API.
func sendTelegram(ctx context.Context, token, chatID, text string) error {
	body, _ := json.Marshal(map[string]string{
		"chat_id": chatID,
		"text":    text,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api returned %d", resp.StatusCode)
	}
	return nil
}

// NotifyStatus reports whether notifications are configured (read-only).
func NotifyStatus(ctx context.Context, _ map[string]any) (map[string]any, error) {
	_, _, ok := notifyConfig()
	return map[string]any{
		"enabled":     ok,
		"configured":  ok,
		"channel":     "telegram",
		"needs_token": !ok,
	}, nil
}

// NotifyTest sends a test message to the configured chat. If not configured it
// returns a clear "dependency not ready" — never a fake success.
func NotifyTest(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("notify.test requires parameters")
	}
	for k := range params {
		if k != "message" {
			return nil, fmt.Errorf("unsupported field: %s", k)
		}
	}
	token, chatID, ok := notifyConfig()
	if !ok {
		return map[string]any{
			"ok":            false,
			"error":         "依赖未就绪：未配置 Telegram bot token（OCP_AGENT_NOTIFY_TOKEN / OCP_AGENT_NOTIFY_CHAT_ID）",
			"not_configured": true,
		}, nil
	}
	msg, _ := params["message"].(string)
	if strings.TrimSpace(msg) == "" {
		msg = "OrangeCatPanel 通知测试"
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	if err := sendTelegram(ctx, token, chatID, msg); err != nil {
		return map[string]any{"ok": false, "error": "发送失败: " + err.Error()}, nil
	}
	return map[string]any{"ok": true, "sent": true, "chat_id": chatID}, nil
}

// NotifyAlert raises an alert. In production the alert rules live in a config
// file (/etc/ocp/notify-rules.json); without a token, alerts are refused.
func NotifyAlert(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("notify.alert requires parameters")
	}
	for k := range params {
		if k != "severity" && k != "message" {
			return nil, fmt.Errorf("unsupported field: %s", k)
		}
	}
	severity, _ := params["severity"].(string)
	if severity == "" {
		severity = "info"
	}
	if severity != "info" && severity != "warning" && severity != "critical" {
		return nil, fmt.Errorf("severity must be info/warning/critical")
	}
	msg, _ := params["message"].(string)
	if strings.TrimSpace(msg) == "" {
		return nil, fmt.Errorf("message is required")
	}
	token, chatID, ok := notifyConfig()
	if !ok {
		return map[string]any{
			"ok":             false,
			"error":          "依赖未就绪：未配置 Telegram bot token",
			"not_configured": true,
		}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	text := fmt.Sprintf("🔔 [%s] %s", strings.ToUpper(severity), msg)
	if err := sendTelegram(ctx, token, chatID, text); err != nil {
		return map[string]any{"ok": false, "error": "发送失败: " + err.Error()}, nil
	}
	return map[string]any{"ok": true, "sent": true, "severity": severity, "chat_id": chatID}, nil
}
