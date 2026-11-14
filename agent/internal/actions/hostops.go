package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// All handlers read REAL host state. No cached/panel-side values are returned.

// SystemInfo: hostname, distro, kernel, uptime.
func SystemInfo(ctx context.Context, _ map[string]any) (map[string]any, error) {
	data := map[string]any{}
	if fi, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		data["hostname"] = strings.TrimSpace(string(fi))
	}
	if fi, err := os.ReadFile("/etc/os-release"); err == nil {
		// PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
		for _, line := range strings.Split(string(fi), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				data["distro"] = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	if fi, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		data["kernel"] = strings.TrimSpace(string(fi))
	}
	if fi, err := os.ReadFile("/proc/uptime"); err == nil {
		if f, err := strconv.ParseFloat(strings.Fields(string(fi))[0], 64); err == nil {
			data["uptime_seconds"] = int64(f)
		}
	}
	if fi, err := os.ReadFile("/etc/hostname"); err == nil {
		data["hostname_file"] = strings.TrimSpace(string(fi))
	}
	arch, _ := os.ReadFile("/proc/sys/kernel/arch")
	if len(arch) == 0 {
		out, err := exec.CommandContext(ctx, "uname", "m").Output()
		if err == nil {
			data["arch"] = strings.TrimSpace(string(out))
		} else {
			data["arch"] = "unknown"
		}
	} else {
		data["arch"] = strings.TrimSpace(string(arch))
	}
	return data, nil
}

// SystemMetrics: CPU, memory, disk, load — read directly from /proc.
func SystemMetrics(ctx context.Context, _ map[string]any) (map[string]any, error) {
	data := map[string]any{}

	// CPU: /proc/stat first line; sample twice 250ms apart for utilization.
	type cpuSample struct{ idle, total uint64 }
	if c1, ok1 := readCPUStat(); ok1 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		if c2, ok2 := readCPUStat(); ok2 {
			idleDelta := c2.idle - c1.idle
			totalDelta := c2.total - c1.total
			if totalDelta > 0 {
				data["cpu_percent"] = round1(100.0 * float64(totalDelta-idleDelta) / float64(totalDelta))
			}
		}
	}
	// Cores
	if fi, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		data["cpu_cores"] = strings.Count(string(fi), "processor")
	}
	// Load
	if fi, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(fi))
		if len(fields) >= 3 {
			l1, _ := strconv.ParseFloat(fields[0], 64)
			l5, _ := strconv.ParseFloat(fields[1], 64)
			l15, _ := strconv.ParseFloat(fields[2], 64)
			data["load_1m"] = l1
			data["load_5m"] = l5
			data["load_15m"] = l15
		}
	}
	// Memory
	if fi, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		for _, line := range strings.Split(string(fi), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				total = parseKB(line)
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				avail = parseKB(line)
			}
		}
		if total > 0 {
			data["mem_total_mb"] = total / 1024
			data["mem_used_mb"] = (total - avail) / 1024
			data["mem_used_percent"] = round1(100.0 * float64(total-avail) / float64(total))
		}
	}
	// Disk (root filesystem)
	if fi, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(fi), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[1] != "/" {
				continue
			}
			data["disk_fs"] = fields[2]
			break
		}
	}
	out, err := exec.CommandContext(ctx, "df", "-B1", "--output=size,used,avail", "/").Output()
	if err == nil {
		if total, used, parseErr := parseDFOutput(string(out)); parseErr == nil {
			data["disk_total_gb"] = total / 1024 / 1024 / 1024
			data["disk_used_gb"] = used / 1024 / 1024 / 1024
			data["disk_used_percent"] = round1(100.0 * float64(used) / float64(total))
		}
	}
	return data, nil
}

func parseDFOutput(output string) (totalBytes, usedBytes uint64, err error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		return 0, 0, fmt.Errorf("df output must have header and one data row")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 3 {
		return 0, 0, fmt.Errorf("df data row must contain size, used, available")
	}
	totalBytes, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	usedBytes, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if totalBytes == 0 || usedBytes > totalBytes {
		return 0, 0, fmt.Errorf("invalid df size values")
	}
	return totalBytes, usedBytes, nil
}

func readCPUStat() (c struct{ idle, total uint64 }, ok bool) {
	fi, err := os.ReadFile("/proc/stat")
	if err != nil {
		return c, false
	}
	lines := strings.SplitN(string(fi), "\n", 2)
	if len(lines) < 1 {
		return c, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 {
		return c, false
	}
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		c.total += v
		if i == 4 { // idle field index
			c.idle = v
		}
	}
	return c, true
}

func parseKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// DockerSummary: counts + health of containers/images/volumes via docker CLI (fixed args only).
func DockerSummary(ctx context.Context, _ map[string]any) (map[string]any, error) {
	data := map[string]any{}
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.Containers}} {{.Images}}").Output()
	if err != nil {
		data["available"] = false
		data["error"] = err.Error()
		return data, nil
	}
	fields := strings.Fields(string(out))
	if len(fields) == 2 {
		data["containers"] = fields[0]
		data["images"] = fields[1]
	}
	data["available"] = true
	if out, err := exec.CommandContext(ctx, "docker", "volume", "ls", "-q").Output(); err == nil {
		vol := strings.Split(strings.TrimSpace(string(out)), "\n")
		data["volumes"] = len(vol)
	}
	return data, nil
}

// DockerContainers: live container list with state.
func DockerContainers(ctx context.Context, p map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--format",
		`{"name":"{{.Names}}","state":"{{.State}}","status":"{{.Status}}","image":"{{.Image}}","ports":"{{.Ports}}"}`).Output()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}, nil
	}
	// docker --format emits NDJSON (one object per line), not a JSON array.
	var list []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var one map[string]any
		if err := dec.Decode(&one); err != nil {
			break
		}
		list = append(list, one)
	}
	if list == nil {
		list = []map[string]any{}
	}
	return map[string]any{"available": true, "containers": list, "count": len(list)}, nil
}

// NginxSites: scan /home/web/conf.d and /etc/nginx/conf.d for server_name entries.
func NginxSites(ctx context.Context, _ map[string]any) (map[string]any, error) {
	dirs := []string{"/home/web/conf.d", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"}
	var sites []map[string]any
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			b, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			content := string(b)
			names := extractServerNames(content)
			certInfo := extractCertPaths(content)
			sites = append(sites, map[string]any{
				"file":  full,
				"names": names,
				"certs": certInfo,
			})
		}
	}
	if sites == nil {
		sites = []map[string]any{}
	}
	return map[string]any{"sites": sites, "count": len(sites)}, nil
}

func extractServerNames(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "server_name") {
			t = strings.TrimPrefix(t, "server_name")
			t = strings.TrimSuffix(strings.TrimRight(t, ";"), " ")
			out = append(out, strings.Fields(t)...)
		}
	}
	return out
}

func extractCertPaths(content string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "ssl_certificate ") {
			res["cert"] = strings.TrimRight(strings.TrimPrefix(t, "ssl_certificate"), ";")
		}
		if strings.HasPrefix(t, "ssl_certificate_key ") {
			res["key"] = strings.TrimRight(strings.TrimPrefix(t, "ssl_certificate_key"), ";")
		}
	}
	return res
}

// NetInterfaces: rx/tx byte counters per interface from /sys.
func NetInterfaces(ctx context.Context, _ map[string]any) (map[string]any, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var ifaces []map[string]any
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join("/sys/class/net", name)
		rx, _ := os.ReadFile(filepath.Join(base, "statistics", "rx_bytes"))
		tx, _ := os.ReadFile(filepath.Join(base, "statistics", "tx_bytes"))
		speed, _ := os.ReadFile(filepath.Join(base, "speed"))
		ifc := map[string]any{"name": name}
		if len(rx) > 0 {
			v, _ := strconv.ParseUint(strings.TrimSpace(string(rx)), 10, 64)
			ifc["rx_bytes"] = v
		}
		if len(tx) > 0 {
			v, _ := strconv.ParseUint(strings.TrimSpace(string(tx)), 10, 64)
			ifc["tx_bytes"] = v
		}
		if len(speed) > 0 {
			v, _ := strconv.Atoi(strings.TrimSpace(string(speed)))
			ifc["speed_mbps"] = v
		}
		ifaces = append(ifaces, ifc)
	}
	return map[string]any{"interfaces": ifaces}, nil
}

// Processes: top-N by RSS from /proc/<pid>/stat.
func Processes(ctx context.Context, p map[string]any) (map[string]any, error) {
	topN := 20
	for key := range p {
		if key != "top" {
			return nil, fmt.Errorf("unsupported process query parameter")
		}
	}
	if raw, exists := p["top"]; exists {
		value, ok := raw.(float64)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) || value < 1 || value > 100 {
			return nil, fmt.Errorf("process top limit must be an integer from 1 to 100")
		}
		topN = int(value)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	type proc struct {
		pid   int
		name  string
		rssMB float64
	}
	var procs []proc
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statB, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// comm is in parens; find last ')' to avoid comm containing ')'
		idx := strings.LastIndex(string(statB), ") ")
		if idx < 0 {
			continue
		}
		rest := strings.Fields(string(statB)[idx+2:])
		if len(rest) < 22 {
			continue
		}
		// After ") ": rest[0]=field 3 (state); RSS is field 24 → rest[21] (pages × 4KB).
		rssPages, _ := strconv.ParseFloat(rest[21], 64)
		procName := string(statB)[strings.Index(string(statB), "(")+1 : idx]
		procs = append(procs, proc{pid, procName, rssPages * 4.0 / 1024})
	}
	// sort desc by rss
	sort.Slice(procs, func(i, j int) bool { return procs[i].rssMB > procs[j].rssMB })
	if len(procs) > topN {
		procs = procs[:topN]
	}
	out := []map[string]any{}
	for _, pr := range procs {
		out = append(out, map[string]any{"pid": pr.pid, "name": pr.name, "rss_mb": round1(pr.rssMB)})
	}
	return map[string]any{"processes": out}, nil
}

// round2 helper for display
func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

var _ = io.Discard
