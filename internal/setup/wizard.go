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
	"github.com/charmbracelet/lipgloss"

	"github.com/patra/satpam-agent/internal/config"
)

// ── Styles ───────────────────────────────────────────────────────────────────

var (
	styLogo = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E63946")).
		Bold(true)

	stySub = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6B7280"))

	styGreen = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FF41"))

	styText = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E2E8F0"))

	styDim = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#374151"))

	stySep = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1E293B"))

	styOK = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FF41")).
		Bold(true)
)

// ── ASCII Art ─────────────────────────────────────────────────────────────────

// SATPAM rendered in standard figlet font.
const logo = ` ____    _  _____  ____   _    __  __
/ ___|  / \|_   _||  _ \ / \  |  \/  |
\___ \ / _ \ | |  | |_) / _ \ | |\/| |
 ___) / ___ \| |  |  __/ ___ \| |  | |
|____/_/   \_\_|  |_| /_/   \_\_|  |_|`

// infoRow renders a metasploit-style info row:
//
//	       =[ content                                         ]
//	 + -- -=[ content                                         ]
func infoRow(prefix, content string) string {
	const w = 50
	padded := content + strings.Repeat(" ", max(0, w-len(content)))
	return styDim.Render(prefix) +
		styGreen.Render("=[") +
		" " + styText.Render(padded) + " " +
		styGreen.Render("]")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printBanner() {
	fmt.Print("\033[2J\033[H") // clear screen
	fmt.Println()
	fmt.Println(styLogo.Render(logo))
	fmt.Println()
	fmt.Println(stySub.Render("      Security Agent for Threat & Penetration Monitoring"))
	fmt.Println()
	fmt.Println(infoRow("       ", "satpam-agent"))
	fmt.Println(infoRow(" + -- -", fmt.Sprintf("OS: %-10s  Arch: %s", runtime.GOOS, runtime.GOARCH)))
	fmt.Println(infoRow(" + -- -", "First Run Setup -- Configuration Wizard"))
	fmt.Println()
	fmt.Println(stySep.Render("  " + strings.Repeat("─", 62)))
	fmt.Println()
}

// ── Form Theme ────────────────────────────────────────────────────────────────

func hackerTheme() *huh.Theme {
	t := huh.ThemeBase()

	focused := &t.Focused
	focused.Base = focused.Base.BorderForeground(lipgloss.Color("#00FF41"))
	focused.Title = focused.Title.Foreground(lipgloss.Color("#00FF41")).Bold(true)
	focused.Description = focused.Description.Foreground(lipgloss.Color("#4B5563"))
	focused.TextInput.Cursor = focused.TextInput.Cursor.Foreground(lipgloss.Color("#00FF41"))
	focused.TextInput.Placeholder = focused.TextInput.Placeholder.Foreground(lipgloss.Color("#374151"))
	focused.TextInput.Text = focused.TextInput.Text.Foreground(lipgloss.Color("#E2E8F0"))
	focused.ErrorMessage = focused.ErrorMessage.Foreground(lipgloss.Color("#E63946"))
	focused.ErrorIndicator = focused.ErrorIndicator.Foreground(lipgloss.Color("#E63946"))

	blurred := &t.Blurred
	blurred.Title = blurred.Title.Foreground(lipgloss.Color("#4B5563"))
	blurred.TextInput.Text = blurred.TextInput.Text.Foreground(lipgloss.Color("#6B7280"))
	blurred.TextInput.Placeholder = blurred.TextInput.Placeholder.Foreground(lipgloss.Color("#374151"))

	t.Focused.Base = t.Focused.Base.BorderForeground(lipgloss.Color("#00FF41"))
	t.FieldSeparator = lipgloss.NewStyle().SetString("\n")

	return t
}

// ── Wizard ────────────────────────────────────────────────────────────────────

// RunWizard runs the interactive first-run setup and returns the saved config.
// Called only when ~/.satpam-agent/config.yaml does not exist.
func RunWizard(ctx context.Context) (*config.AgentConfig, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-agent"
	}

	printBanner()

	serverURL := "http://localhost:8080"
	machineName := ""

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
				Title("Machine Name").
				Description(fmt.Sprintf("Agent identifier. Leave blank to use hostname (%s).", hostname)).
				Placeholder(hostname).
				Value(&machineName),
		),
	).WithTheme(hackerTheme())

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
		ServerURL: serverURL,
		AgentID:   agentID,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Interval:  "5m",
		Workers:   4,
	}
	if err := config.Save(cfg); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	fmt.Println()
	fmt.Println(styOK.Render("  [+] Config saved  -> ~/.satpam-agent/config.yaml"))
	fmt.Println(styOK.Render("  [+] Agent ID      -> " + agentID))
	fmt.Println(styOK.Render("  [+] Starting satpam-agent ..."))
	fmt.Println()
	return cfg, nil
}

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
		return fmt.Errorf("server returned HTTP %d (expected 200 OK)", resp.StatusCode)
	}
	return nil
}
