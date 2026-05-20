package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/patra/satpam-agent/internal/client"
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

func mockServer(t *testing.T, scanDir string) (*httptest.Server, *[]map[string]interface{}, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var received []map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/rules":
			rs := map[string]interface{}{
				"version":    "1.0.0",
				"updated_at": "2026-05-19T00:00:00Z",
				"yara_rules": minimalRule,
				"scan_config": map[string]interface{}{
					"paths":            []string{scanDir},
					"extensions":       []string{".php"},
					"max_file_size_mb": 10,
					"exclude_dirs":     []string{},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rs)

		case "/v1/findings":
			var batch []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			mu.Lock()
			received = append(received, batch...)
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)

		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &received, &mu
}

func TestIntegration_MaliciousFile_AlertsWithAgentID(t *testing.T) {
	const agentID = "satpam-integration-agent"

	dir := t.TempDir()
	maliciousPath := filepath.Join(dir, "backdoor.php")
	if err := os.WriteFile(maliciousPath, []byte("start "+testMarker+" end"), 0644); err != nil {
		t.Fatal(err)
	}

	srv, received, mu := mockServer(t, dir)
	defer srv.Close()

	c := client.NewClient(srv.URL, agentID)
	if err := runScan(context.Background(), c, 2); err != nil {
		t.Fatalf("runScan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(*received) == 0 {
		t.Fatal("no findings sent to server — expected at least one alert")
	}
	f := (*received)[0]

	if id, _ := f["agent_id"].(string); id != agentID {
		t.Errorf("agent_id: got %q, want %q", id, agentID)
	}
	if fp, _ := f["file_path"].(string); !strings.HasSuffix(fp, "backdoor.php") {
		t.Errorf("file_path: got %q, expected suffix 'backdoor.php'", fp)
	}
	if rn, _ := f["rule_name"].(string); rn == "" {
		t.Error("rule_name must not be empty")
	}
	if sv, _ := f["severity"].(string); sv == "" {
		t.Error("severity must not be empty")
	}
}

func TestIntegration_CleanDirectory_NoAlerts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte(`<?php echo "Hello, World!"; ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	alertSent := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/rules":
			rs := map[string]interface{}{
				"version":    "1.0.0",
				"updated_at": "2026-05-19T00:00:00Z",
				"yara_rules": minimalRule,
				"scan_config": map[string]interface{}{
					"paths":            []string{dir},
					"extensions":       []string{".php"},
					"max_file_size_mb": 10,
					"exclude_dirs":     []string{},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rs)
		case "/v1/findings":
			alertSent = true
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	c := client.NewClient(srv.URL, "clean-agent")
	if err := runScan(context.Background(), c, 2); err != nil {
		t.Fatal(err)
	}
	if alertSent {
		t.Error("alert sent for a clean directory — false positive")
	}
}

func TestIntegration_MultipleShells_AllAlerted(t *testing.T) {
	const agentID = "batch-agent-99"

	dir := t.TempDir()
	for _, name := range []string{"shell1.php", "shell2.php", "shell3.php"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(testMarker), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "safe.php"), []byte(`<?php echo 1; ?>`), 0644); err != nil {
		t.Fatal(err)
	}

	srv, received, mu := mockServer(t, dir)
	defer srv.Close()

	c := client.NewClient(srv.URL, agentID)
	if err := runScan(context.Background(), c, 4); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(*received) != 3 {
		t.Errorf("expected 3 findings (one per shell), got %d", len(*received))
	}
	for i, f := range *received {
		if id, _ := f["agent_id"].(string); id != agentID {
			t.Errorf("finding[%d] agent_id: got %q, want %q", i, id, agentID)
		}
	}
}

func TestIntegration_VendorExcluded_ShellNotAlerted(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendor, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "shell.php"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var received []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/rules":
			rs := map[string]interface{}{
				"version":    "1.0.0",
				"updated_at": "2026-05-19T00:00:00Z",
				"yara_rules": minimalRule,
				"scan_config": map[string]interface{}{
					"paths":            []string{dir},
					"extensions":       []string{".php"},
					"max_file_size_mb": 10,
					"exclude_dirs":     []string{"vendor"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rs)
		case "/v1/findings":
			var batch []map[string]interface{}
			json.NewDecoder(r.Body).Decode(&batch)
			mu.Lock()
			received = append(received, batch...)
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	c := client.NewClient(srv.URL, "vendor-test-agent")
	if err := runScan(context.Background(), c, 2); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Errorf("expected 0 alerts (vendor excluded), got %d", len(received))
	}
}

func TestIntegration_AgentID_RecordedByServer(t *testing.T) {
	const hostname = "web-prod-03.cluster.internal"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil.php"), []byte(testMarker), 0644); err != nil {
		t.Fatal(err)
	}

	srv, received, mu := mockServer(t, dir)
	defer srv.Close()

	c := client.NewClient(srv.URL, hostname)
	if err := runScan(context.Background(), c, 2); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*received) == 0 {
		t.Fatal("no findings received")
	}
	for i, f := range *received {
		if id, _ := f["agent_id"].(string); id != hostname {
			t.Errorf("finding[%d]: agent_id = %q, want %q", i, id, hostname)
		}
	}
}

func TestIntegration_FindingContainsMatchedOn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shell.php"), []byte("prefix "+testMarker+" suffix"), 0644); err != nil {
		t.Fatal(err)
	}

	srv, received, mu := mockServer(t, dir)
	defer srv.Close()

	c := client.NewClient(srv.URL, "matched-on-test-agent")
	if err := runScan(context.Background(), c, 2); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*received) == 0 {
		t.Fatal("no findings received")
	}
	if mo, _ := (*received)[0]["matched_on"].(string); mo == "" {
		t.Error("matched_on should be populated so operators know what triggered the alert")
	}
}
