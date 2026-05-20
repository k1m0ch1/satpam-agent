package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/patra/satpam-agent/internal/yara"
)

const (
	testMarker = "SATPAM_UNIT_TEST_CANARY_XZ42"

	minimalRule = `
rule Test_SatpamCanary {
    meta:
        description = "synthetic satpam unit-test marker"
        severity = "high"
    strings:
        $s1 = "SATPAM_UNIT_TEST_CANARY_XZ42" nocase
    condition:
        any of them
}
`
)

func TestNewScanner_DefaultsMaxFileMB(t *testing.T) {
	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{MaxFileMB: 0}
	sc := NewScanner(rules, cfg, 1)
	want := int64(10 * 1024 * 1024)
	if sc.maxBytes != want {
		t.Errorf("maxBytes: got %d, want %d", sc.maxBytes, want)
	}
}

func TestNewScanner_ExtSetBuilt(t *testing.T) {
	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Extensions: []string{".PHP", ".JSP"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 1)
	if !sc.extSet[".php"] {
		t.Error("extSet should contain lowercase .php")
	}
	if !sc.extSet[".jsp"] {
		t.Error("extSet should contain lowercase .jsp")
	}
	if sc.extSet[".txt"] {
		t.Error("extSet should not contain .txt")
	}
}

func TestNewScanner_SkipSetBuilt(t *testing.T) {
	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{ExcludeDirs: []string{"Vendor", "NODE_MODULES"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 1)
	if !sc.skipSet["vendor"] {
		t.Error("skipSet should contain lowercase 'vendor'")
	}
	if !sc.skipSet["node_modules"] {
		t.Error("skipSet should contain lowercase 'node_modules'")
	}
}

func TestScanFile_DetectsMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(path, []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	sc := NewScanner(rules, ScanConfig{MaxFileMB: 1}, 1)
	buf := make([]byte, sc.maxBytes)

	findings, err := sc.scanFile(path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].FilePath != path {
		t.Errorf("file_path: got %q, want %q", findings[0].FilePath, path)
	}
	if findings[0].RuleName != "Test_SatpamCanary" {
		t.Errorf("rule_name: got %q, want %q", findings[0].RuleName, "Test_SatpamCanary")
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity: got %q, want %q", findings[0].Severity, "high")
	}
	if findings[0].MatchedOn == "" {
		t.Error("matched_on must not be empty")
	}
}

func TestScanFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.php")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	sc := NewScanner(rules, ScanConfig{MaxFileMB: 1}, 1)
	buf := make([]byte, sc.maxBytes)

	findings, err := sc.scanFile(path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("empty file: expected 0 findings, got %d", len(findings))
	}
}

func TestScanFile_CleanFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.php")
	if err := os.WriteFile(path, []byte(`<?php echo "Hello, World!"; ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	sc := NewScanner(rules, ScanConfig{MaxFileMB: 1}, 1)
	buf := make([]byte, sc.maxBytes)

	findings, err := sc.scanFile(path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("clean file: expected 0 findings, got %d", len(findings))
	}
}

func TestScanFile_MissingFile(t *testing.T) {
	rules, _ := yara.ParseRules(minimalRule)
	sc := NewScanner(rules, ScanConfig{MaxFileMB: 1}, 1)
	buf := make([]byte, sc.maxBytes)

	_, err := sc.scanFile("/nonexistent/path/shell.php", buf)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestScan_DetectsMarkerInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backdoor.php")
	if err := os.WriteFile(path, []byte("prefix "+testMarker+" suffix"), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Paths: []string{dir}, Extensions: []string{".php"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 2)

	findings, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}
	f := findings[0]
	if f.FilePath != path {
		t.Errorf("file_path: got %q, want %q", f.FilePath, path)
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q, want %q", f.Severity, "high")
	}
	if f.MatchedOn == "" {
		t.Error("matched_on should not be empty")
	}
}

func TestScan_CleanDirectoryNoFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(`<?php echo "safe"; ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Paths: []string{dir}, Extensions: []string{".php"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 2)

	findings, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("clean dir: expected 0 findings, got %d", len(findings))
	}
}

func TestScan_ExtensionFilterSkipsNonTargetFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Paths: []string{dir}, Extensions: []string{".php"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 2)

	findings, _ := sc.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("extension filter failed: got %d findings for .txt file", len(findings))
	}
}

func TestScan_ExcludeDirSkipsSubtree(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "shell.php"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{
		Paths:       []string{dir},
		Extensions:  []string{".php"},
		MaxFileMB:   1,
		ExcludeDirs: []string{"vendor"},
	}
	sc := NewScanner(rules, cfg, 2)

	findings, _ := sc.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("exclude dir failed: got %d findings inside vendor/", len(findings))
	}
}

func TestScan_ExcludedDirCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	nodeModules := filepath.Join(dir, "Node_Modules")
	if err := os.MkdirAll(nodeModules, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "evil.php"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{
		Paths:       []string{dir},
		Extensions:  []string{".php"},
		MaxFileMB:   1,
		ExcludeDirs: []string{"node_modules"},
	}
	sc := NewScanner(rules, cfg, 2)
	findings, _ := sc.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("case-insensitive dir exclusion failed: got %d findings", len(findings))
	}
}

func TestScan_MultipleFilesAllReported(t *testing.T) {
	dir := t.TempDir()
	shells := []string{"shell1.php", "shell2.php", "shell3.php"}
	for _, name := range shells {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(testMarker), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "safe.php"), []byte(`<?php echo 1; ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Paths: []string{dir}, Extensions: []string{".php"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 4)

	findings, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (one per shell), got %d", len(findings))
	}
}

func TestScan_ContextCancel_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shell.php"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{Paths: []string{dir}, Extensions: []string{".php"}, MaxFileMB: 1}
	sc := NewScanner(rules, cfg, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sc.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScan_NonexistentPath_ReturnsEmpty(t *testing.T) {
	rules, _ := yara.ParseRules(minimalRule)
	cfg := ScanConfig{
		Paths:      []string{"/definitely/does/not/exist"},
		Extensions: []string{".php"},
		MaxFileMB:  1,
	}
	sc := NewScanner(rules, cfg, 2)
	findings, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("nonexistent path: expected 0 findings, got %d", len(findings))
	}
}
