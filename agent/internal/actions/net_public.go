package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// P16: public network info (public IPv4/IPv6, operator).
//
// Public IP is fetched from a real external API with a short timeout.
// On failure the fields report "未识别" honestly — never fabricate an IP
// or an operator. Local addresses come from `ip -4 addr` (real system state).
//
// 外部 API 选型：优先 ipapi.co（免费、含 ASN 组织名 = 运营商），失败回落
// ipify（纯 IP）。两者都失败则诚实报"未识别"。

const publicIPTimout = 5 * time.Second

type publicIPInfo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
}

// NetPublic returns real public + local network identity.
func NetPublic(ctx context.Context, _ map[string]any) (map[string]any, error) {
	res := map[string]any{
		"public_ipv4": "未识别",
		"public_ipv6": "未识别",
		"operator":    "未识别",
		"city":        "未识别",
		"source":      "未查询",
	}
	// 1. 本地 IP 真实读取（ip -4/-6 addr）
	res["local_ipv4"] = localAddr("4")
	res["local_ipv6"] = localAddr("6")
	// 2. 公网 IP + 运营商（外部 API，失败诚实）
	info, src, err := fetchPublicIP(ctx)
	if err != nil {
		res["public_error"] = err.Error()
		return res, nil
	}
	res["public_ipv4"] = info.IP
	res["operator"] = info.Org
	res["city"] = info.City
	res["source"] = src
	// 3. 公网 IPv6（api64 端点，独立尝试；只有真 IPv6 格式才认）
	if v6, err := fetchPublicIPv6(ctx); err == nil && strings.Contains(v6, ":") {
		res["public_ipv6"] = v6
	}
	return res, nil
}

// localAddr reads the primary non-loopback address for a given family ("4"/"6").
func localAddr(family string) string {
	bin, err := exec.Command("ip", "-"+family, "addr", "show").Output()
	if err != nil {
		return "未识别"
	}
	lines := strings.Split(string(bin), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "inet") {
			// "inet 192.168.1.5/24 ..." — take the address part
			fields := strings.Fields(ln)
			if len(fields) >= 2 {
				addr := strings.Split(fields[1], "/")[0]
				if addr != "127.0.0.1" && addr != "::1" && addr != "" {
					return addr
				}
			}
		}
	}
	return "未识别"
}

// fetchPublicIP queries ipapi.co (ASN org = operator), falls back to ipify.
func fetchPublicIP(ctx context.Context) (publicIPInfo, string, error) {
	ctx, cancel := context.WithTimeout(ctx, publicIPTimout)
	defer cancel()
	// Try ipapi.co first (has operator info).
	if info, err := queryIPAPI(ctx, "https://ipapi.co/json/"); err == nil {
		return info, "ipapi.co", nil
	}
	// Fallback: ipify only gives IP (operator stays 未识别).
	if ip, err := queryIPify(ctx, "https://api.ipify.org?format=json"); err == nil {
		return publicIPInfo{IP: ip, Org: "未识别"}, "ipify", nil
	}
	return publicIPInfo{}, "", fmt.Errorf("公网 IP 查询失败（ipapi.co 与 ipify 均不可达）")
}

func queryIPAPI(ctx context.Context, url string) (publicIPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return publicIPInfo{}, err
	}
	req.Header.Set("User-Agent", "OrangeCatPanel/0.10")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return publicIPInfo{}, err
	}
	defer resp.Body.Close()
	var info publicIPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return publicIPInfo{}, err
	}
	if info.IP == "" {
		return publicIPInfo{}, fmt.Errorf("ipapi 返回空 IP")
	}
	return info, nil
}

func queryIPify(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "OrangeCatPanel/0.10")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.IP, nil
}

func fetchPublicIPv6(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, publicIPTimout)
	defer cancel()
	return queryIPify(ctx, "https://api64.ipify.org?format=json")
}
