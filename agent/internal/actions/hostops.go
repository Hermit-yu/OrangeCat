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
		var total, avail, buffers, cached, shared, swapTotal, swapFree uint64
		for _, line := range strings.Split(string(fi), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				total = parseKB(line)
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				avail = parseKB(line)
			}
			if strings.HasPrefix(line, "Buffers:") {
				buffers = parseKB(line)
			}
			if strings.HasPrefix(line, "Cached:") {
				cached = parseKB(line)
			}
			if strings.HasPrefix(line, "Shmem:") {
				shared = parseKB(line)
			}
			if strings.HasPrefix(line, "SwapTotal:") {
				swapTotal = parseKB(line)
			}
			if strings.HasPrefix(line, "SwapFree:") {
				swapFree = parseKB(line)
			}
		}
		if total > 0 {
			data["mem_total_mb"] = total / 1024
			data["mem_used_mb"] = (total - avail) / 1024
			data["mem_used_percent"] = round1(100.0 * float64(total-avail) / float64(total))
			data["mem_buffers_mb"] = buffers / 1024
			data["mem_cached_mb"] = cached / 1024
			data["mem_shared_mb"] = shared / 1024
		}
		if swapTotal > 0 {
			swapUsed := swapTotal - swapFree
			data["swap_total_mb"] = swapTotal / 1024
			data["swap_used_mb"] = swapUsed / 1024
			data["swap_used_percent"] = round1(100.0 * float64(swapUsed) / float64(swapTotal))
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
	outI, errI := exec.CommandContext(ctx, "df", "-B1", "--output=itotal,iused,iavail", "/").Output()
	if errI == nil {
		if itotal, iused, parseErr := parseDFInodeOutput(string(outI)); parseErr == nil {
			data["disk_inodes_total"] = itotal
			data["disk_inodes_used"] = iused
			data["disk_inodes_used_percent"] = round1(100.0 * float64(iused) / float64(itotal))
		}
	}
	return data, nil
}

func parseDFInodeOutput(output string) (totalInodes, usedInodes uint64, err error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		return 0, 0, fmt.Errorf("df -i output must have header and one data row")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 3 {
		return 0, 0, fmt.Errorf("df -i data row must contain itotal, iused, iavail")
	}
	totalInodes, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	usedInodes, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if totalInodes == 0 || usedInodes > totalInodes {
		return 0, 0, fmt.Errorf("invalid df -i inode values")
	}
	return totalInodes, usedInodes, nil
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

// NetInterfaces: rx/tx byte and packet counters, errors and drops per interface from /sys.
func NetInterfaces(ctx context.Context, _ map[string]any) (map[string]any, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var ifaces []map[string]any
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join("/sys/class/net", name)
		ifc := map[string]any{"name": name}
		readSysStat := func(field string, key string) {
			if b, err := os.ReadFile(filepath.Join(base, "statistics", field)); err == nil {
				if v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
					ifc[key] = v
				}
			}
		}
		readSysStat("rx_bytes", "rx_bytes")
		readSysStat("tx_bytes", "tx_bytes")
		readSysStat("rx_packets", "rx_packets")
		readSysStat("tx_packets", "tx_packets")
		readSysStat("rx_errors", "rx_errors")
		readSysStat("tx_errors", "tx_errors")
		readSysStat("rx_dropped", "rx_dropped")
		readSysStat("tx_dropped", "tx_dropped")
		if speed, err := os.ReadFile(filepath.Join(base, "speed")); err == nil {
			if v, err := strconv.Atoi(strings.TrimSpace(string(speed))); err == nil {
				ifc["speed_mbps"] = v
			}
		}
		ifaces = append(ifaces, ifc)
	}
	return map[string]any{"interfaces": ifaces}, nil
}

// Processes: top-N by RSS from /proc/<pid>/stat.
// readTotalCPUTicks reads the total CPU jiffies from /proc/stat first line.
// Returns 0 if unavailable; caller treats 0 as "no CPU baseline" (cpuPct=0).
func readTotalCPUTicks() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// cpu user nice system idle iowait irq softirq steal guest guest_nice
		var total float64
		for _, f := range fields[1:] {
			v, err := strconv.ParseFloat(f, 64)
			if err != nil {
				continue
			}
			total += v
		}
		return total
	}
	return 0
}

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
		pid       int
		name      string
		uid       string
		rssMB     float64
		startTick int64
		state     string
		cpuPct    float64
		cpuJiffs  float64 // utime+stime at first sample
	}
	var procs []proc
	totalProcs := 0
	runningProcs := 0
	// 第一遍：全系统扫描，收集进程元数据 + 第一采样 CPU jiffies。
	// 进程数/运行中为全系统真实计数（不只 top20）。
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
		// Field 22 (starttime, clock ticks) is rest[19]; used for PID-reuse
		// protection at kill time.
		startTick, _ := strconv.ParseInt(rest[19], 10, 64)
		// Field 14 (utime) + field 15 (stime) → rest[11] + rest[12]（用户态+内核态 jiffies）。
		utime, _ := strconv.ParseFloat(rest[11], 64)
		stime, _ := strconv.ParseFloat(rest[12], 64)
		procName := string(statB)[strings.Index(string(statB), "(")+1 : idx]
		uid := readProcUID(pid)
		totalProcs++
		if rest[0] == "R" {
			runningProcs++
		}
		procs = append(procs, proc{pid, procName, uid, rssPages * 4.0 / 1024, startTick, rest[0], 0, utime + stime})
	}
	// sort desc by rss
	sort.Slice(procs, func(i, j int) bool { return procs[i].rssMB > procs[j].rssMB })
	if len(procs) > topN {
		procs = procs[:topN]
	}
	// 瞬时 CPU：两采样差值。第一遍已取 t1；间隔约 300ms 后取 t2。
	// cpuPct = Δproc_jiffies / Δsystem_total_jiffies × 100 × 核数（占单核，top 语义，可 >100）。
	sysT1 := readTotalCPUTicks()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(300 * time.Millisecond):
	}
	sysT2 := readTotalCPUTicks()
	sysDelta := sysT2 - sysT1
	if sysDelta <= 0 {
		sysDelta = 1 // 防除零；无基准则 cpuPct=0
	}
	nCPU := numCPUs()
	for i := range procs {
		b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(procs[i].pid), "stat"))
		if err != nil {
			continue // 进程已退出，保留第一采样（cpuPct=0 合理）
		}
		idx := strings.LastIndex(string(b), ") ")
		if idx < 0 {
			continue
		}
		rest := strings.Fields(string(b)[idx+2:])
		if len(rest) < 13 {
			continue
		}
		u2, _ := strconv.ParseFloat(rest[11], 64)
		s2, _ := strconv.ParseFloat(rest[12], 64)
		procs[i].cpuPct = (u2 + s2 - procs[i].cpuJiffs) / sysDelta * 100 * float64(nCPU)
		if procs[i].cpuPct < 0 {
			procs[i].cpuPct = 0
		}
	}
	out := []map[string]any{}
	for _, pr := range procs {
		out = append(out, map[string]any{"pid": pr.pid, "name": pr.name, "uid": pr.uid, "rss_mb": round1(pr.rssMB), "start_time": pr.startTick, "state": pr.state, "cpu_pct": round1(pr.cpuPct)})
	}
	// 运行实体数：/proc/loadavg 第 4 字段第一段（内核权威瞬时值，含内核线程）。
	// 全系统扫描时 R 进程是毫秒级状态，扫描耗时>10ms 必然漏掉大部分，
	// 用 loadavg 的运行实体计数更可靠（不恒 0）。
	if lb, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(lb))
		if len(fields) >= 4 {
			if r := strings.SplitN(fields[3], "/", 2); len(r) > 0 {
				if n, err := strconv.Atoi(r[0]); err == nil {
					runningProcs = n
				}
			}
		}
	}
	return map[string]any{"processes": out, "total_processes": totalProcs, "running_processes": runningProcs}, nil
}

// numCPUs returns the number of online CPUs (from /proc/stat cpuN lines), min 1.
func numCPUs() int {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 1
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	if n < 1 {
		return 1
	}
	return n
}

// readProcUID returns the real uid from /proc/<pid>/status, or "unknown".
func readProcUID(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "status"))
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1]
			}
			break
		}
	}
	return "unknown"
}

// round2 helper for display
func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

var _ = io.Discard
