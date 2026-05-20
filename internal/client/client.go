package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/patra/satpam-agent/internal/inventory"
	"github.com/patra/satpam-agent/internal/scanner"
)

// Client communicates with a satpam-server instance.
type Client struct {
	base       string
	agentID    string
	token      string
	httpClient *http.Client
}

func NewClient(base, agentID, token string) *Client {
	return &Client{
		base:       base,
		agentID:    agentID,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// ── Rules ─────────────────────────────────────────────────────────────────────

// RuleSet is the response payload from GET /v1/rules.
type RuleSet struct {
	Version    string            `json:"version"`
	UpdatedAt  time.Time         `json:"updated_at"`
	YARARules  string            `json:"yara_rules"`
	ScanConfig scanner.ScanConfig `json:"scan_config"`
}

func (c *Client) FetchRules(ctx context.Context) (*RuleSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/rules", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch rules: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d on /v1/rules", resp.StatusCode)
	}
	var rs RuleSet
	return &rs, json.NewDecoder(resp.Body).Decode(&rs)
}

// ── Findings ──────────────────────────────────────────────────────────────────

type reportedFinding struct {
	AgentID   string `json:"agent_id"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	FilePath  string `json:"file_path"`
	MatchedOn string `json:"matched_on"`
	Snippet   string `json:"snippet,omitempty"`
}

func (c *Client) ReportFindings(ctx context.Context, findings []scanner.Finding) error {
	payload := make([]reportedFinding, len(findings))
	for i, f := range findings {
		payload[i] = reportedFinding{
			AgentID:   c.agentID,
			RuleName:  f.RuleName,
			Severity:  f.Severity,
			FilePath:  f.FilePath,
			MatchedOn: f.MatchedOn,
			Snippet:   f.Snippet,
		}
	}
	return c.postJSON(ctx, "/v1/findings", payload, http.StatusAccepted)
}

// ── Inventory ─────────────────────────────────────────────────────────────────

type inventoryPayload struct {
	AgentID     string                   `json:"agent_id"`
	OS          string                   `json:"os"`
	Arch        string                   `json:"arch"`
	Hostname    string                   `json:"hostname"`
	CollectedAt time.Time                `json:"collected_at"`
	Software    []inventory.SoftwareEntry `json:"software"`
}

func (c *Client) ReportInventory(ctx context.Context, software []inventory.SoftwareEntry) error {
	hostname, _ := os.Hostname()
	p := inventoryPayload{
		AgentID:     c.agentID,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname,
		CollectedAt: time.Now().UTC(),
		Software:    software,
	}
	return c.postJSON(ctx, "/v1/inventory", p, http.StatusAccepted)
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

type heartbeatPayload struct {
	AgentID  string `json:"agent_id"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
}

func (c *Client) Heartbeat(ctx context.Context) error {
	hostname, _ := os.Hostname()
	p := heartbeatPayload{
		AgentID:  c.agentID,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
	}
	return c.postJSON(ctx, "/v1/heartbeat", p, http.StatusNoContent)
}

// ── Commands ──────────────────────────────────────────────────────────────────

// Command is a directive received from the server.
type Command struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Type    string `json:"type"`
	Status  string `json:"status"`
}

func (c *Client) FetchCommands(ctx context.Context) ([]Command, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/v1/commands?agent_id="+c.agentID, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch commands: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d on /v1/commands", resp.StatusCode)
	}
	var cmds []Command
	return cmds, json.NewDecoder(resp.Body).Decode(&cmds)
}

func (c *Client) AckCommand(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/v1/commands/"+id+"/ack", nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ack command: %w", err)
	}
	resp.Body.Close()
	return nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (c *Client) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) postJSON(ctx context.Context, path string, body any, wantStatus int) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("POST %s returned %d", path, resp.StatusCode)
	}
	return nil
}
