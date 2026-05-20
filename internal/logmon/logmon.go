// Package logmon tails log files and ships events to satpam-server.
package logmon

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// LogEvent is a single parsed log line.
type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"` // "nginx_access" | "nginx_error" | "ufw"
	FilePath  string    `json:"file_path"`
	Raw       string    `json:"raw"`
	Level     string    `json:"level,omitempty"`  // info | warn | error | critical
	IP        string    `json:"ip,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    int       `json:"status,omitempty"`
}

// Source defines a log file to monitor.
type Source struct {
	Path   string
	Name   string
	Parser func(line string) *LogEvent
}

// DefaultSources returns the default log sources for the current OS.
func DefaultSources() []Source {
	if runtime.GOOS != "linux" {
		return nil
	}
	return []Source{
		{
			Path:   "/var/log/nginx/access.log",
			Name:   "nginx_access",
			Parser: parseNginxAccess,
		},
		{
			Path:   "/var/log/nginx/error.log",
			Name:   "nginx_error",
			Parser: parseNginxError,
		},
		{
			Path:   "/var/log/ufw.log",
			Name:   "ufw",
			Parser: parseUFW,
		},
		{
			Path:   "/var/log/syslog",
			Name:   "syslog",
			Parser: parseSyslog,
		},
	}
}

// Watcher tails one log file and sends events to a channel.
type Watcher struct {
	src    Source
	out    chan<- LogEvent
	offset int64
}

func newWatcher(src Source, out chan<- LogEvent) *Watcher {
	return &Watcher{src: src, out: out}
}

func (w *Watcher) run(ctx context.Context) {
	// Seek to end on first open so we don't replay history.
	f, err := os.Open(w.src.Path)
	if err != nil {
		return // file doesn't exist yet, skip silently
	}
	if info, err := f.Stat(); err == nil {
		w.offset, _ = f.Seek(0, io.SeekEnd)
		_ = info
	}
	f.Close()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.poll()
		}
	}
}

func (w *Watcher) poll() {
	f, err := os.Open(w.src.Path)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}

	// Detect log rotation: file is smaller than our last position.
	if info.Size() < w.offset {
		w.offset = 0
	}

	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ev := w.src.Parser(line)
		if ev == nil {
			ev = &LogEvent{
				Timestamp: time.Now().UTC(),
				Source:    w.src.Name,
				FilePath:  w.src.Path,
				Raw:       line,
				Level:     "info",
			}
		}
		select {
		case w.out <- *ev:
		default: // drop if channel full
		}
	}
	w.offset, _ = f.Seek(0, io.SeekCurrent)
}

// Monitor starts all default log watchers and returns events on the channel.
// The caller is responsible for draining the channel.
func Monitor(ctx context.Context, srcs []Source) <-chan LogEvent {
	ch := make(chan LogEvent, 512)
	for _, src := range srcs {
		go newWatcher(src, ch).run(ctx)
	}
	return ch
}

// MonitorCustom watches an additional list of paths with auto-detected parser.
func MonitorCustom(ctx context.Context, paths []string) <-chan LogEvent {
	var srcs []Source
	for _, p := range paths {
		p := p
		name := filepath.Base(p)
		srcs = append(srcs, Source{
			Path:   p,
			Name:   name,
			Parser: autoParser(p),
		})
	}
	return Monitor(ctx, srcs)
}

func autoParser(path string) func(string) *LogEvent {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "nginx") && strings.Contains(base, "access"):
		return parseNginxAccess
	case strings.Contains(base, "nginx") && strings.Contains(base, "error"):
		return parseNginxError
	case strings.Contains(base, "ufw"):
		return parseUFW
	default:
		return parseSyslog
	}
}

// ── Parsers ───────────────────────────────────────────────────────────────────

// Nginx combined log format:
// 127.0.0.1 - - [01/Jan/2026:12:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "-" "curl/7.68"
var nginxAccessRe = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) ([^\s"]+)[^"]*" (\d+) `,
)

func parseNginxAccess(line string) *LogEvent {
	m := nginxAccessRe.FindStringSubmatch(line)
	if len(m) < 6 {
		return nil
	}
	var status int
	statusStr := m[5]
	for _, c := range statusStr {
		status = status*10 + int(c-'0')
	}
	level := "info"
	if status >= 500 {
		level = "error"
	} else if status >= 400 {
		level = "warn"
	}
	return &LogEvent{
		Timestamp: time.Now().UTC(),
		Source:    "nginx_access",
		Raw:       line,
		Level:     level,
		IP:        m[1],
		Method:    m[3],
		Path:      m[4],
		Status:    status,
	}
}

// Nginx error log:
// 2026/01/01 12:00:00 [error] 1234#0: *1 ...
var nginxErrorRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(\w+)\]`)

func parseNginxError(line string) *LogEvent {
	m := nginxErrorRe.FindStringSubmatch(line)
	level := "error"
	if len(m) >= 2 {
		level = strings.ToLower(m[1])
	}
	return &LogEvent{
		Timestamp: time.Now().UTC(),
		Source:    "nginx_error",
		Raw:       line,
		Level:     level,
	}
}

// UFW log:
// May 20 10:00:01 host kernel: [123.456] UFW BLOCK IN=eth0 OUT= ...SRC=1.2.3.4 DST=...
var ufwIPRe = regexp.MustCompile(`SRC=(\S+)`)

func parseUFW(line string) *LogEvent {
	if !strings.Contains(line, "UFW") {
		return nil
	}
	level := "warn"
	if strings.Contains(line, "UFW BLOCK") {
		level = "error"
	}
	ip := ""
	if m := ufwIPRe.FindStringSubmatch(line); len(m) >= 2 {
		ip = m[1]
	}
	return &LogEvent{
		Timestamp: time.Now().UTC(),
		Source:    "ufw",
		Raw:       line,
		Level:     level,
		IP:        ip,
	}
}

// Generic syslog parser.
func parseSyslog(line string) *LogEvent {
	level := "info"
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "fatal"):
		level = "error"
	case strings.Contains(lower, "warn"):
		level = "warn"
	case strings.Contains(lower, "critical"):
		level = "critical"
	}
	return &LogEvent{
		Timestamp: time.Now().UTC(),
		Source:    "syslog",
		Raw:       line,
		Level:     level,
	}
}

// Batch collects at most maxBatch events that arrive within window, then sends.
func Batch(ctx context.Context, in <-chan LogEvent, maxBatch int, window time.Duration, send func([]LogEvent)) {
	var buf []LogEvent
	timer := time.NewTimer(window)
	defer timer.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := make([]LogEvent, len(buf))
		copy(batch, buf)
		buf = buf[:0]
		go func() {
			if err := ctx.Err(); err == nil {
				send(batch)
			}
		}()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(window)
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev, ok := <-in:
			if !ok {
				flush()
				return
			}
			ev.FilePath = "" // populated by watcher, caller can set
			buf = append(buf, ev)
			if len(buf) >= maxBatch {
				flush()
			}
		case <-timer.C:
			flush()
			timer.Reset(window)
		}
	}
}

// LogSummary provides quick stats about what the log watcher has seen.
type LogSummary struct {
	Source     string `json:"source"`
	TotalLines int64  `json:"total_lines"`
	Errors     int64  `json:"errors"`
	Warns      int64  `json:"warns"`
}

// Debug helper for testing parsers.
func ParseLine(source, line string) *LogEvent {
	srcs := map[string]func(string) *LogEvent{
		"nginx_access": parseNginxAccess,
		"nginx_error":  parseNginxError,
		"ufw":          parseUFW,
		"syslog":       parseSyslog,
	}
	if p, ok := srcs[source]; ok {
		return p(line)
	}
	return nil
}

// suppress unused slog warning
var _ = slog.Info
