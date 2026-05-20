package metrics

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Snapshot holds a single point-in-time system snapshot.
type Snapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemUsed       uint64    `json:"mem_used_bytes"`
	MemTotal      uint64    `json:"mem_total_bytes"`
	MemPercent    float64   `json:"mem_percent"`
	DiskUsed      uint64    `json:"disk_used_bytes"`
	DiskTotal     uint64    `json:"disk_total_bytes"`
	DiskPercent   float64   `json:"disk_percent"`
	LoadAvg1      float64   `json:"load_avg_1m,omitempty"`
	UptimeSeconds uint64    `json:"uptime_seconds,omitempty"`
}

// Collect gathers a system snapshot. CPU is sampled over ~500ms.
func Collect(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{Timestamp: time.Now().UTC()}
	switch runtime.GOOS {
	case "linux":
		collectLinux(ctx, s)
	case "darwin":
		collectDarwin(ctx, s)
	case "windows":
		collectWindows(ctx, s)
	}
	return s, nil
}

// ── Linux ──────────────────────────────────────────────────────────────────────

func collectLinux(ctx context.Context, s *Snapshot) {
	s.CPUPercent, _ = linuxCPU(ctx)
	s.MemUsed, s.MemTotal, s.MemPercent = linuxMem()
	s.DiskUsed, s.DiskTotal, s.DiskPercent = unixDisk("/")
	s.UptimeSeconds = linuxUptime()
	s.LoadAvg1 = linuxLoadAvg()
}

func linuxCPU(ctx context.Context) (float64, error) {
	read := func() (idle, total uint64, err error) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)[1:]
			var vals [10]uint64
			for i, v := range fields {
				if i >= 10 {
					break
				}
				vals[i], _ = strconv.ParseUint(v, 10, 64)
			}
			idle = vals[3] + vals[4]
			for _, v := range vals {
				total += v
			}
			return
		}
		return 0, 0, fmt.Errorf("no cpu line")
	}

	idle1, total1, err := read()
	if err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}
	idle2, total2, err := read()
	if err != nil {
		return 0, err
	}
	dtotal := float64(total2 - total1)
	if dtotal == 0 {
		return 0, nil
	}
	return (1.0 - float64(idle2-idle1)/dtotal) * 100, nil
}

func linuxMem() (used, total uint64, pct float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	var memTotal, memAvail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		var val uint64
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), " %d", &val)
			memTotal = val * 1024
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemAvailable:"), " %d", &val)
			memAvail = val * 1024
		}
	}
	if memTotal == 0 {
		return
	}
	total = memTotal
	used = memTotal - memAvail
	pct = float64(used) / float64(total) * 100
	return
}

func linuxUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var secs float64
	fmt.Sscanf(string(data), "%f", &secs)
	return uint64(secs)
}

func linuxLoadAvg() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	var avg float64
	fmt.Sscanf(string(data), "%f", &avg)
	return avg
}

// ── macOS ─────────────────────────────────────────────────────────────────────

func collectDarwin(ctx context.Context, s *Snapshot) {
	s.CPUPercent = darwinCPU(ctx)
	s.MemUsed, s.MemTotal, s.MemPercent = darwinMem()
	s.DiskUsed, s.DiskTotal, s.DiskPercent = unixDisk("/")
	s.UptimeSeconds = darwinUptime()
}

func darwinCPU(_ context.Context) float64 {
	out, err := runCmd(5*time.Second, "sh", "-c",
		"top -l 2 -s 1 -n 0 | awk '/CPU usage/{last=$0} END{print last}'")
	if err != nil {
		return 0
	}
	line := strings.TrimSpace(string(out))
	var idle float64
	fmt.Sscanf(line[strings.LastIndex(line, ",")+1:], " %f", &idle)
	return 100 - idle
}

func darwinMem() (used, total uint64, pct float64) {
	out, err := runCmd(3*time.Second, "sysctl", "-n", "hw.memsize")
	if err != nil {
		return
	}
	total, _ = strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)

	out2, err := runCmd(3*time.Second, "vm_stat")
	if err != nil || total == 0 {
		return
	}
	var active, wired uint64
	const pageSize = 4096
	sc := bufio.NewScanner(bytes.NewReader(out2))
	for sc.Scan() {
		line := sc.Text()
		var val uint64
		if strings.HasPrefix(line, "Pages active:") {
			fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(line, "Pages active:"), "."), " %d", &val)
			active = val * pageSize
		} else if strings.HasPrefix(line, "Pages wired down:") {
			fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(line, "Pages wired down:"), "."), " %d", &val)
			wired = val * pageSize
		}
	}
	used = active + wired
	pct = float64(used) / float64(total) * 100
	return
}

func darwinUptime() uint64 {
	out, err := runCmd(3*time.Second, "sysctl", "-n", "kern.boottime")
	if err != nil {
		return 0
	}
	var sec uint64
	fmt.Sscanf(string(out), "{ sec = %d", &sec)
	if sec == 0 {
		return 0
	}
	return uint64(time.Now().Unix()) - sec
}

// ── Windows ───────────────────────────────────────────────────────────────────

func collectWindows(ctx context.Context, s *Snapshot) {
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$os = Get-CimInstance Win32_OperatingSystem
$disk = Get-CimInstance -Query "SELECT FreeSpace,Size FROM Win32_LogicalDisk WHERE DeviceID='C:'"
Write-Output "cpu=$cpu memfree=$($os.FreePhysicalMemory) memtotal=$($os.TotalVisibleMemorySize) diskfree=$($disk.FreeSpace) disktotal=$($disk.Size) uptime=$([int]((Get-Date)-$os.LastBootUpTime).TotalSeconds)"`).Output()
	if err != nil {
		return
	}
	for _, field := range strings.Fields(string(out)) {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "cpu":
			v, _ := strconv.ParseFloat(kv[1], 64)
			s.CPUPercent = v
		case "memfree":
			v, _ := strconv.ParseUint(kv[1], 10, 64)
			s.MemUsed -= v * 1024
		case "memtotal":
			v, _ := strconv.ParseUint(kv[1], 10, 64)
			s.MemTotal = v * 1024
			s.MemUsed = s.MemTotal
		case "diskfree":
			v, _ := strconv.ParseUint(kv[1], 10, 64)
			s.DiskUsed -= v
		case "disktotal":
			v, _ := strconv.ParseUint(kv[1], 10, 64)
			s.DiskTotal = v
			s.DiskUsed = s.DiskTotal
		case "uptime":
			v, _ := strconv.ParseUint(kv[1], 10, 64)
			s.UptimeSeconds = v
		}
	}
	if s.MemTotal > 0 {
		s.MemPercent = float64(s.MemUsed) / float64(s.MemTotal) * 100
	}
	if s.DiskTotal > 0 {
		s.DiskPercent = float64(s.DiskUsed) / float64(s.DiskTotal) * 100
	}
}

// ── Shared ─────────────────────────────────────────────────────────────────────

// unixDisk uses "df -B1 <path>" which works on Linux and macOS.
func unixDisk(path string) (used, total uint64, pct float64) {
	out, err := runCmd(5*time.Second, "df", "-B1", path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return
	}
	// Filesystem 1B-blocks Used Available Use% Mounted on
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return
	}
	total, _ = strconv.ParseUint(fields[1], 10, 64)
	used, _ = strconv.ParseUint(fields[2], 10, 64)
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return
}

func runCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
