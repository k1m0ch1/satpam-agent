package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/patra/satpam-agent/internal/scanner"
)

const minimalRule = `
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

func TestFetchRules_ParsesResponse(t *testing.T) {
	want := RuleSet{
		Version:   "2.0.0",
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		YARARules: minimalRule,
		ScanConfig: scanner.ScanConfig{
			Paths:      []string{"/var/www"},
			Extensions: []string{".php", ".jsp"},
			MaxFileMB:  5,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/rules" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-agent")
	got, err := c.FetchRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version {
		t.Errorf("version: got %q, want %q", got.Version, want.Version)
	}
	if got.YARARules != want.YARARules {
		t.Error("yara_rules mismatch")
	}
	if len(got.ScanConfig.Paths) != 1 || got.ScanConfig.Paths[0] != "/var/www" {
		t.Errorf("paths: got %v", got.ScanConfig.Paths)
	}
	if got.ScanConfig.MaxFileMB != 5 {
		t.Errorf("max_file_size_mb: got %d, want 5", got.ScanConfig.MaxFileMB)
	}
}

func TestFetchRules_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "agent-1")
	_, err := c.FetchRules(context.Background())
	if err == nil {
		t.Error("expected error on 503, got nil")
	}
}

func TestFetchRules_ServerDown_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close()

	c := NewClient(addr, "agent-1")
	c.httpClient.Timeout = 200 * time.Millisecond
	_, err := c.FetchRules(context.Background())
	if err == nil {
		t.Error("expected error when server is closed, got nil")
	}
}

func TestFetchRules_InvalidJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json {{{"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "agent-1")
	_, err := c.FetchRules(context.Background())
	if err == nil {
		t.Error("expected error on invalid JSON, got nil")
	}
}

func TestReportFindings_IncludesAgentID(t *testing.T) {
	const wantAgentID = "host-007"

	type payload struct {
		AgentID   string `json:"agent_id"`
		RuleName  string `json:"rule_name"`
		Severity  string `json:"severity"`
		FilePath  string `json:"file_path"`
		MatchedOn string `json:"matched_on"`
		Snippet   string `json:"snippet"`
	}
	var received []payload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/findings" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, wantAgentID)
	findings := []scanner.Finding{
		{
			RuleName:  "Test_SatpamCanary",
			Severity:  "high",
			FilePath:  "/var/www/html/shell.php",
			MatchedOn: "$s1 = SATPAM_UNIT_TEST_CANARY_XZ42",
			Snippet:   "...SATPAM_UNIT_TEST_CANARY_XZ42...",
		},
	}
	if err := c.ReportFindings(context.Background(), findings); err != nil {
		t.Fatal(err)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 finding sent to server, got %d", len(received))
	}
	got := received[0]
	if got.AgentID != wantAgentID {
		t.Errorf("agent_id: got %q, want %q", got.AgentID, wantAgentID)
	}
	if got.RuleName != "Test_SatpamCanary" {
		t.Errorf("rule_name: got %q, want %q", got.RuleName, "Test_SatpamCanary")
	}
	if got.Severity != "high" {
		t.Errorf("severity: got %q, want %q", got.Severity, "high")
	}
	if got.FilePath != "/var/www/html/shell.php" {
		t.Errorf("file_path: got %q", got.FilePath)
	}
}

func TestReportFindings_MultipleFindingsBatched(t *testing.T) {
	var receivedCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var findings []map[string]interface{}
		json.NewDecoder(r.Body).Decode(&findings)
		receivedCount = len(findings)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "batch-agent")
	findings := []scanner.Finding{
		{RuleName: "Rule_A", Severity: "critical", FilePath: "/a.php"},
		{RuleName: "Rule_B", Severity: "high", FilePath: "/b.php"},
		{RuleName: "Rule_C", Severity: "medium", FilePath: "/c.php"},
	}
	if err := c.ReportFindings(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if receivedCount != 3 {
		t.Errorf("expected 3 findings in one batch, got %d", receivedCount)
	}
}

func TestReportFindings_AgentIDInAllBatchedFindings(t *testing.T) {
	const wantID = "satpam-node-42"
	var received []map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, wantID)
	findings := []scanner.Finding{
		{RuleName: "Rule_A", Severity: "high", FilePath: "/a.php"},
		{RuleName: "Rule_B", Severity: "high", FilePath: "/b.php"},
	}
	c.ReportFindings(context.Background(), findings)

	for i, f := range received {
		if id, _ := f["agent_id"].(string); id != wantID {
			t.Errorf("finding[%d] agent_id: got %q, want %q", i, id, wantID)
		}
	}
}

func TestReportFindings_Server500_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "agent-1")
	err := c.ReportFindings(context.Background(), []scanner.Finding{{RuleName: "x", Severity: "high"}})
	if err == nil {
		t.Error("expected error on server 500, got nil")
	}
}

func TestReportFindings_ContextCancelled_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewClient(srv.URL, "agent-1")
	err := c.ReportFindings(ctx, []scanner.Finding{{RuleName: "x", Severity: "high"}})
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}
