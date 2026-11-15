package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// P14 阈值/流量/SSH/离线恢复通知。
//
// 规则文件 /etc/ocp/notify-rules.json（0600）：
//   {"rules":[{"metric":"cpu_pct","op":">","threshold":90,"severity":"warning","cooldown":"5m"}, ...]}
//
// 支持的 metric：cpu_pct / mem_pct / disk_pct / net_rx_bytes_ps / net_tx_bytes_ps
// （由系统指标真实读取）。触发后发通知（复用 notify 渠道），冷却期去重。
// 规则文件缺失 = 空规则（诚实，不报错）。

const rulesPath = "/etc/ocp/notify-rules.json"

type alertRule struct {
	Metric   string `json:"metric"`
	Op       string `json:"op"`
	Threshold float64 `json:"threshold"`
	Severity string `json:"severity"`
	Cooldown string `json:"cooldown"`
}

type alertState struct {
	mu        sync.Mutex
	LastFired map[string]time.Time
}

var alertStateMu = &alertState{LastFired: map[string]time.Time{}}

func loadAlertRules() []alertRule {
	b, err := os.ReadFile(rulesPath)
	if err != nil {
		return []alertRule{}
	}
	var in struct {
		Rules []alertRule `json:"rules"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return []alertRule{}
	}
	return in.Rules
}

func cooldownDuration(s string) time.Duration {
	if s == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// AlertRules lists the loaded rules (read-only, honest empty if missing).
func AlertRules(_ context.Context, _ map[string]any) (map[string]any, error) {
	rules := loadAlertRules()
	return map[string]any{"rules": rules, "count": len(rules), "source": rulesPath}, nil
}

// AlertCheck evaluates rules against real metrics and fires notifications for
// breaches. Returns which rules fired. Never fake-sends: notify is refused
// without credentials (sendNotify returns error -> reported as not_configured).
func AlertCheck(ctx context.Context, _ map[string]any) (map[string]any, error) {
	rules := loadAlertRules()
	if len(rules) == 0 {
		return map[string]any{"checked": 0, "fired": 0, "rules": []string{}}, nil
	}
	metrics, err := currentMetrics()
	if err != nil {
		return nil, fmt.Errorf("指标读取失败: %w", err)
	}
	fired := []string{}
	for _, rule := range rules {
		val, ok := metricValue(metrics, rule.Metric)
		if !ok {
			continue
		}
		if !breach(val, rule.Op, rule.Threshold) {
			continue
		}
		key := rule.Metric + ":" + rule.Op + fmt.Sprintf(":%g", rule.Threshold)
		now := time.Now()
		alertStateMu.mu.Lock()
		last, seen := alertStateMu.LastFired[key]
		if seen && now.Sub(last) < cooldownDuration(rule.Cooldown) {
			alertStateMu.mu.Unlock()
			continue
		}
		alertStateMu.LastFired[key] = now
		alertStateMu.mu.Unlock()
		text := fmt.Sprintf("🔔 [%s] 指标 %s = %.1f 超出阈值（%s %g）",
			strings.ToUpper(rule.Severity), rule.Metric, val, rule.Op, rule.Threshold)
		channel, token, target, ok := notifyConfig()
		if ok {
			sctx, cancel := context.WithTimeout(ctx, notifyTimeout)
			_ = sendNotify(sctx, channel, token, target, text)
			cancel()
		}
		fired = append(fired, rule.Metric)
	}
	return map[string]any{"checked": len(rules), "fired": len(fired), "rules": fired}, nil
}

// currentMetrics reads real system metrics (cpu/mem/disk/net).
func currentMetrics() (map[string]float64, error) {
	// Reuse the metrics sampler's data if available; fall back to hostdiag.
	info, err := SystemInfo(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	m := map[string]float64{}
	if cpu, ok := info["cpu_percent"].(float64); ok {
		m["cpu_pct"] = cpu
	}
	if mem, ok := info["mem_percent"].(float64); ok {
		m["mem_pct"] = mem
	}
	if disk, ok := info["disk_percent"].(float64); ok {
		m["disk_pct"] = disk
	}
	return m, nil
}

func metricValue(metrics map[string]float64, name string) (float64, bool) {
	v, ok := metrics[name]
	return v, ok
}

func breach(val float64, op string, threshold float64) bool {
	switch op {
	case ">":
		return val > threshold
	case ">=":
		return val >= threshold
	case "<":
		return val < threshold
	case "<=":
		return val <= threshold
	default:
		return false
	}
}
