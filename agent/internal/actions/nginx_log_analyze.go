package actions

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// P7：基于真实 nginx access.log 的访问量/流量/响应码分析。
//
// 只读：扫描日志文件尾部（有界），解析标准 combined 格式，统计指定时间窗
// 内的请求数、字节数、响应码分布、按站点/路径分组。不写任何文件。
//
// 安全模型：路径固定为 nginx 访问日志挂载（/home/web/log/nginx/access.log），
// 不接收任意路径；只读尾部 maxBytes（默认 8 MiB），避免大文件全读。

const (
	nginxAccessLogPath = "/home/web/log/nginx/access.log"
	nginxLogMaxBytes   = 8 << 20
	nginxLogTimeout    = 20 * time.Second
)

// hostStat / pathStat are package-level so the sort helpers and the handler
// share the same types.
type hostStat struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
	Bytes int64  `json:"bytes"`
}

type pathStat struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// NginxLogAnalyze scans the real access log tail and returns stats.
// params: window_minutes (default 60), top (default 10).
func NginxLogAnalyze(ctx context.Context, params map[string]any) (map[string]any, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("nginx.log.analyze requires parameters")
	}
	for k := range params {
		if k != "window_minutes" && k != "top" {
			return nil, fmt.Errorf("unsupported field: %s", k)
		}
	}
	windowMin := 60
	if v, ok := params["window_minutes"].(float64); ok && v > 0 {
		windowMin = int(v)
	}
	if v, ok := params["window_minutes"].(int); ok && v > 0 {
		windowMin = v
	}
	topN := 10
	if v, ok := params["top"].(float64); ok && v > 0 {
		topN = int(v)
	}
	if v, ok := params["top"].(int); ok && v > 0 {
		topN = v
	}
	if windowMin > 1440 {
		windowMin = 1440
	}
	if topN > 50 {
		topN = 50
	}

	ctx, cancel := context.WithTimeout(ctx, nginxLogTimeout)
	defer cancel()

	f, err := os.Open(nginxAccessLogPath)
	if err != nil {
		return nil, fmt.Errorf("open access log: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat access log: %w", err)
	}
	// Seek to the tail (bounded) so we only scan recent lines.
	start := fi.Size() - nginxLogMaxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, fmt.Errorf("seek access log: %w", err)
	}
	// If we didn't land on a line start, discard the first partial line.
	if start > 0 {
		buf := make([]byte, 1)
		_, _ = f.Read(buf)
		// We are mid-line; skip to next newline.
		rd := bufio.NewReader(f)
		_, _ = rd.ReadString('\n')
		f.Seek(start, 0)
		_ = rd
	}

	cutoff := time.Now().Add(-time.Duration(windowMin) * time.Minute).Unix()

	type agg struct {
		count    int
		bytes    int64
		statuses map[string]int
		paths    map[string]int
	}
	total := &agg{statuses: map[string]int{}, paths: map[string]int{}}
	byIP := map[string]*agg{}
	var scanned int

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		scanned++
		ts, ip, path, status, bytes, ok := parseAccessLine(line)
		if !ok || ts < cutoff {
			continue
		}
		add := func(a *agg) {
			a.count++
			a.bytes += bytes
			a.statuses[status]++
			a.paths[path]++
		}
		add(total)
		if ip != "" {
			if byIP[ip] == nil {
				byIP[ip] = &agg{statuses: map[string]int{}, paths: map[string]int{}}
			}
			add(byIP[ip])
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan access log: %w", err)
	}

	// Response code classes.
	codeClasses := map[string]int{}
	for code, n := range total.statuses {
		cls := code + "xx"
		if len(code) == 3 {
			cls = code[:1] + "xx"
		}
		codeClasses[cls] += n
	}

	// Top source IPs.
	hosts := []hostStat{}
	for ip, a := range byIP {
		hosts = append(hosts, hostStat{Host: ip, Count: a.count, Bytes: a.bytes})
	}
	sortHosts(hosts)

	// Top paths.
	paths := []pathStat{}
	for p, n := range total.paths {
		paths = append(paths, pathStat{Path: p, Count: n})
	}
	sortPaths(paths)

	// Trim to topN.
	if len(hosts) > topN {
		hosts = hosts[:topN]
	}
	if len(paths) > topN {
		paths = paths[:topN]
	}

	return map[string]any{
		"log_file":      nginxAccessLogPath,
		"window_minutes": windowMin,
		"scanned":       scanned,
		"requests":      total.count,
		"bytes_total":   total.bytes,
		"bytes_per_req": float64(total.bytes) / float64(maxInt(total.count, 1)),
		"status_classes": codeClasses,
		"top_hosts":     hosts,
		"top_paths":     paths,
	}, nil
}

// parseAccessLine parses a combined-format nginx log line.
// Returns (timestamp, sourceIP, path, status, bytes, ok). The source IP is
// field 1 (remote_addr); the combined format has no Host header field.
func parseAccessLine(line string) (int64, string, string, string, int64, bool) {
	// Standard combined: ip - - [date] "method path proto" status bytes "referer" "ua"
	// Fields split on space; find the request line between quotes.
	first := strings.IndexByte(line, '"')
	if first < 0 {
		return 0, "", "", "", 0, false
	}
	second := strings.IndexByte(line[first+1:], '"')
	if second < 0 {
		return 0, "", "", "", 0, false
	}
	req := line[first+1 : first+1+second] // "GET /path HTTP/1.1"
	reqParts := strings.Fields(req)
	if len(reqParts) < 2 {
		return 0, "", "", "", 0, false
	}
	path := reqParts[1]

	// After the request line: status bytes.
	rest := strings.TrimSpace(line[first+1+second+1:])
	restParts := strings.Fields(rest)
	if len(restParts) < 2 {
		return 0, "", "", "", 0, false
	}
	status := restParts[0]
	bytes, _ := strconv.ParseInt(restParts[1], 10, 64)

	// Source IP: first field (before the first space).
	fields := strings.Fields(line)
	ip := ""
	if len(fields) > 0 {
		ip = fields[0]
	}

	// Timestamp: [07/Oct/2026:02:00:04 +0000] — before the first quote.
	lb := strings.IndexByte(line, '[')
	if lb >= 0 && lb < first {
		rb := strings.IndexByte(line[lb:], ']')
		if rb > 0 {
			tsStr := line[lb+1 : lb+rb]
			parts := strings.SplitN(tsStr, " ", 2)
			if len(parts) == 2 {
				if t, err := time.Parse("02/Jan/2006:15:04:05", parts[0]); err == nil {
					return t.Unix(), ip, path, status, bytes, true
				}
			}
		}
	}
	return 0, ip, path, status, bytes, true
}

func sortHosts(h []hostStat) {
	// insertion sort by count desc (small n)
	for i := 1; i < len(h); i++ {
		for j := i; j > 0 && h[j].Count > h[j-1].Count; j-- {
			h[j], h[j-1] = h[j-1], h[j]
		}
	}
}

func sortPaths(p []pathStat) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Count > p[j-1].Count; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
