package scanner

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/patra/satpam-agent/internal/yara"
)

// ScanConfig controls which files the scanner visits.
type ScanConfig struct {
	Paths       []string `json:"paths"`
	Extensions  []string `json:"extensions"`
	MaxFileMB   int      `json:"max_file_size_mb"`
	ExcludeDirs []string `json:"exclude_dirs"`
}

// Finding is one rule match in one file.
type Finding struct {
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	FilePath  string `json:"file_path"`
	MatchedOn string `json:"matched_on"`
	Snippet   string `json:"snippet,omitempty"`
}

// Scanner walks directories and matches rules concurrently using a worker pool.
type Scanner struct {
	rules    []*yara.Rule
	cfg      ScanConfig
	workers  int
	maxBytes int64
	bufPool  sync.Pool
	extSet   map[string]bool
	skipSet  map[string]bool
}

func NewScanner(rules []*yara.Rule, cfg ScanConfig, workers int) *Scanner {
	mb := cfg.MaxFileMB
	if mb <= 0 {
		mb = 10
	}
	maxBytes := int64(mb) * 1024 * 1024
	s := &Scanner{
		rules:    rules,
		cfg:      cfg,
		workers:  workers,
		maxBytes: maxBytes,
		extSet:   toLookup(cfg.Extensions, strings.ToLower),
		skipSet:  toLookup(cfg.ExcludeDirs, strings.ToLower),
	}
	s.bufPool.New = func() any {
		return make([]byte, maxBytes)
	}
	return s
}

// Scan walks all configured paths and returns every rule match found.
func (s *Scanner) Scan(ctx context.Context) ([]Finding, error) {
	files := make(chan string, s.workers*4)
	out := make(chan Finding, s.workers*4)

	var wg sync.WaitGroup
	for range s.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, files, out)
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	go func() {
		defer close(files)
		for _, p := range s.cfg.Paths {
			s.walk(ctx, p, files)
		}
	}()

	var findings []Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, nil
}

func (s *Scanner) walk(ctx context.Context, root string, out chan<- string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			slog.Warn("walk error", "path", path, "err", err)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if d.IsDir() {
			if s.skipSet[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if s.extSet[strings.ToLower(filepath.Ext(d.Name()))] {
			select {
			case out <- path:
			case <-ctx.Done():
			}
		}
		return nil
	})
}

func (s *Scanner) worker(ctx context.Context, in <-chan string, out chan<- Finding) {
	buf := s.bufPool.Get().([]byte)
	defer s.bufPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			return
		case path, ok := <-in:
			if !ok {
				return
			}
			findings, err := s.scanFile(path, buf)
			if err != nil {
				slog.Debug("scan error", "path", path, "err", err)
				continue
			}
			for _, f := range findings {
				out <- f
			}
		}
	}
}

func (s *Scanner) scanFile(path string, buf []byte) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	data := buf[:n]
	lower := bytes.ToLower(data)

	var findings []Finding
	for _, rule := range s.rules {
		if matched, on, sn := rule.Match(data, lower); matched {
			findings = append(findings, Finding{
				RuleName:  rule.Name,
				Severity:  rule.Severity,
				FilePath:  path,
				MatchedOn: on,
				Snippet:   sn,
			})
		}
	}
	return findings, nil
}

func toLookup(items []string, transform func(string) string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, v := range items {
		m[transform(v)] = true
	}
	return m
}
