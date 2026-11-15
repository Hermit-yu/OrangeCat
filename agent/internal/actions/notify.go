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

// P7/P14：多渠道通知能力。
//
// 凭据从环境变量注入（OCP_AGENT_NOTIFY_TOKEN / OCP_AGENT_NOTIFY_CHAT_ID /
// OCP_AGENT_NOTIFY_CHANNEL），不写死、不落日志。没有配置 token 时所有动作
// 明确返回"依赖未就绪"，不编造发送成功。channel 一次只启用一个：
// telegram（默认）/ feishu / dingtalk / wecom。
//
// 启用纪律（P7 验收）：notify.test 必须先真实抵达指定目标才视为已配置；
// notify.alert 在未配置时拒绝触发。

const notifyTimeout = 15 * time.Second

// notifyConfig holds the channel + credentials from the environment.
func notifyConfig() (channel, token, target string, ok bool) {
	channel = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_CHANNEL"))
	if channel == "" {
		channel = "telegram"
	}
	token = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_TOKEN"))
	switch channel {
	case "telegram":
		target = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_CHAT_ID"))
	case "feishu":
		target = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_FEISHU_WEBHOOK"))
		// feishu webhook is the token itself
		if token == "" {
			token = target
			target = ""
		}
	case "dingtalk":
		target = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_DINGTALK_WEBHOOK"))
		if token == "" {
			token = target
			target = ""
		}
	case "wecom":
		target = strings.TrimSpace(os.Getenv("OCP_AGENT_NOTIFY_WECOM_WEBHOOK"))
		if token == "" {
			token = target
			target = ""
		}
	}
	return channel, token, target, token != ""
}

// sendNotify posts a message to the configured channel.
func sendNotify(ctx context.Context, channel, token, target, text string) error {
	switch channel {
	case "telegram":
		return sendTelegram(ctx, token, target, text)
	case "feishu":
		return sendFeishu(ctx, token, text)
	case "dingtalk":
		return sendDingtalk(ctx, token, text)
	case "wecom":
		return sendWecom(ctx, token, text)
	default:
		return fmt.Errorf("未知通知渠道: %s", channel)
	}
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

// sendFeishu posts a message to a Feishu webhook ({"msg_type":"text","content":{"text":...}}).
func sendFeishu(ctx context.Context, webhook, text string) error {
	body, _ := json.Marshal(map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": text},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
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
		return fmt.Errorf("feishu api returned %d", resp.StatusCode)
	}
	return nil
}

// sendDingtalk posts a message to a DingTalk webhook ({"msgtype":"text","text":{"content":...}}).
func sendDingtalk(ctx context.Context, webhook, text string) error {
	body, _ := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
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
		return fmt.Errorf("dingtalk api returned %d", resp.StatusCode)
	}
	return nil
}

// sendWecom posts a message to a WeCom webhook ({"msgtype":"text","text":{"content":...}}).
func sendWecom(ctx context.Context, webhook, text string) error {
	body, _ := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
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
		return fmt.Errorf("wecom api returned %d", resp.StatusCode)
	}
	return nil
}

// NotifyStatus reports whether notifications are configured (read-only).
func NotifyStatus(ctx context.Context, _ map[string]any) (map[string]any, error) {
	channel, _, _, ok := notifyConfig()
	return map[string]any{
		"enabled":     ok,
		"configured":  ok,
		"channel":     channel,
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
	channel, token, chatID, ok := notifyConfig()
	if !ok {
		return map[string]any{
			"ok":            false,
			"error":         "依赖未就绪：未配置通知凭据（OCP_AGENT_NOTIFY_TOKEN / OCP_AGENT_NOTIFY_CHAT_ID / OCP_AGENT_NOTIFY_CHANNEL）",
			"not_configured": true,
		}, nil
	}
	msg, _ := params["message"].(string)
	if strings.TrimSpace(msg) == "" {
		msg = "OrangeCatPanel 通知测试"
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	if err := sendNotify(ctx, channel, token, chatID, msg); err != nil {
		return map[string]any{"ok": false, "error": "发送失败: " + err.Error()}, nil
	}
	return map[string]any{"ok": true, "sent": true, "channel": channel, "target": chatID}, nil
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
	channel, token, chatID, ok := notifyConfig()
	if !ok {
		return map[string]any{
			"ok":             false,
			"error":          "依赖未就绪：未配置通知凭据",
			"not_configured": true,
		}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	text := fmt.Sprintf("🔔 [%s] %s", strings.ToUpper(severity), msg)
	if err := sendNotify(ctx, channel, token, chatID, text); err != nil {
		return map[string]any{"ok": false, "error": "发送失败: " + err.Error()}, nil
	}
	return map[string]any{"ok": true, "sent": true, "severity": severity, "channel": channel}, nil
}
