package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/patra/satpam-agent/internal/config"
	"github.com/patra/satpam-agent/internal/service"
	"github.com/patra/satpam-agent/internal/tui"
)

func printBanner(reconfig bool) {
	label := "First Run Setup -- Configuration Wizard"
	if reconfig {
		label = "Reconfigure -- Configuration Wizard"
	}
	fmt.Print("\033[2J\033[H")
	tui.PrintCenteredHeader()
	fmt.Println(tui.InfoRow("       ", "satpam-agent"))
	fmt.Println(tui.InfoRow(" + -- -", fmt.Sprintf("OS: %-10s  Arch: %s", runtime.GOOS, runtime.GOARCH)))
	fmt.Println(tui.InfoRow(" + -- -", label))
	fmt.Println()
	fmt.Println(tui.Separator())
	fmt.Println()
}

// RunWizard runs the interactive setup wizard and returns the saved config.
// Pass reconfig=true when triggered by --firsttime to show "Reconfigure" in the banner.
func RunWizard(ctx context.Context, reconfig ...bool) (*config.AgentConfig, error) {
	isReconfig := len(reconfig) > 0 && reconfig[0]
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-agent"
	}

	printBanner(isReconfig)

	serverURL   := "http://localhost:8080"
	serverToken := ""
	machineName := hostname

	if isReconfig {
		if existing, err := config.Load(); err == nil {
			if existing.ServerURL != "" {
				serverURL = existing.ServerURL
			}
			serverToken = existing.ServerToken
			if existing.AgentID != "" {
				machineName = existing.AgentID
			}
		}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Satpam Server URL").
				Description("URL of the satpam-server. Connection is tested on submit.").
				Placeholder("http://localhost:8080").
				Value(&serverURL).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("server URL cannot be empty")
					}
					cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					return tryConnect(cctx, s)
				}),
			huh.NewInput().
				Title("Server Bearer Token").
				Description("Auth token for satpam-server. Leave blank if the server has no auth configured.").
				Placeholder("(paste token here)").
				Value(&serverToken).
				Validate(func(s string) error {
					cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					return tryAuth(cctx, serverURL, strings.TrimSpace(s))
				}),
			huh.NewInput().
				Title("Machine Name").
				Description(fmt.Sprintf("Agent identifier (hostname: %s).", hostname)).
				Placeholder(hostname).
				Value(&machineName),
		),
	).WithTheme(tui.HackerTheme())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, context.Canceled
		}
		return nil, err
	}

	agentID := strings.TrimSpace(machineName)
	if agentID == "" {
		agentID = hostname
	}

	cfg := &config.AgentConfig{
		ServerURL:   serverURL,
		ServerToken: strings.TrimSpace(serverToken),
		AgentID:     agentID,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Interval:    "5m",
		Workers:     4,
	}
	if err := config.Save(cfg); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	fmt.Println()
	fmt.Println(tui.StyleOK.Render("  [+] Config saved  -> ~/.satpam-agent/config.yaml"))
	fmt.Println(tui.StyleOK.Render("  [+] Agent ID      -> " + agentID))
	fmt.Println()

	var installSvc bool
	svcForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Run as background service?").
				Description(service.Description()).
				Affirmative("Yes, install service").
				Negative("No, run manually").
				Value(&installSvc),
		),
	).WithTheme(tui.HackerTheme())

	if err := svcForm.Run(); err == nil && installSvc {
		exe, _ := os.Executable()
		if err := service.Install(exe); err != nil {
			fmt.Fprintf(os.Stderr, "\n%s  service install failed: %v\n", tui.StyleErr.Render("[!]"), err)
		} else {
			fmt.Println(tui.StyleOK.Render("  [+] Service installed and started"))
			for _, hint := range service.ManageHints() {
				fmt.Println(tui.StyleDim.Render("      " + hint))
			}
			fmt.Println()
		}
	} else {
		fmt.Println(tui.StyleOK.Render("  [+] Starting satpam-agent ..."))
		fmt.Println()
	}

	return cfg, nil
}

// tryConnect verifies the server is reachable by hitting /health (auth-exempt).
func tryConnect(ctx context.Context, serverURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach server (connection refused or timed out)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d on /health", resp.StatusCode)
	}
	return nil
}

// tryAuth verifies the token (or absence of one) against an authenticated endpoint.
func tryAuth(ctx context.Context, serverURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/v1/agents", nil)
	if err != nil {
		return nil // URL already validated above
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil // connectivity already checked; don't block on transient errors
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if token == "" {
			return fmt.Errorf("server requires a bearer token — paste the token from satpam-server startup output")
		}
		return fmt.Errorf("token rejected (401 Unauthorized) — double-check the token and try again")
	}
	return nil
}
