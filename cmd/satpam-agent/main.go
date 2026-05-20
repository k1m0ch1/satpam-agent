package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/patra/satpam-agent/internal/client"
	"github.com/patra/satpam-agent/internal/config"
	"github.com/patra/satpam-agent/internal/cve"
	"github.com/patra/satpam-agent/internal/inventory"
	"github.com/patra/satpam-agent/internal/scanner"
	"github.com/patra/satpam-agent/internal/service"
	"github.com/patra/satpam-agent/internal/setup"
	"github.com/patra/satpam-agent/internal/tui"
	"github.com/patra/satpam-agent/internal/updater"
	"github.com/patra/satpam-agent/internal/yara"
)

// version is injected at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── First-run: interactive setup wizard ───────────────────────────────
	if config.IsFirstRun() {
		if _, err := setup.RunWizard(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "\nsatpam-agent: setup failed: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	// ── Always show banner + check for updates ────────────────────────────
	tui.PrintBanner(version)
	updater.CheckAndPrompt(ctx, version)

	// ── Load saved config as flag defaults (CLI flags always win) ─────────
	serverDef   := "http://localhost:8080"
	agentIDDef  := mustHostname()
	intervalDef := 5 * time.Minute
	workersDef  := 4
	tokenDef    := ""

	if cfg, err := config.Load(); err == nil {
		serverDef = cfg.ServerURL
		tokenDef  = cfg.ServerToken
		if cfg.AgentID != "" {
			agentIDDef = cfg.AgentID
		}
		if d, err := time.ParseDuration(cfg.Interval); err == nil && d > 0 {
			intervalDef = d
		}
		if cfg.Workers > 0 {
			workersDef = cfg.Workers
		}
	}

	serverURL  := flag.String("server", serverDef, "satpam-server base URL")
	serverToken := flag.String("token", tokenDef, "Bearer token for satpam-server auth")
	interval   := flag.Duration("interval", intervalDef, "scan interval (0 = run once and exit)")
	workers    := flag.Int("workers", workersDef, "parallel scan workers")
	agentID    := flag.String("id", agentIDDef, "agent identifier sent with findings")
	installSvc := flag.Bool("systemd", false, "install as background service and exit")
	stackMode  := flag.Bool("stack", false, "run software inventory + CVE scan, then exit")
	flag.Parse()

	// ── Service install ───────────────────────────────────────────────────
	if *installSvc {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s  resolve executable: %v\n", tui.StyleErr.Render("[!]"), err)
			os.Exit(1)
		}
		exe, _ = filepath.EvalSymlinks(exe)
		if service.IsInstalled() {
			fmt.Println(tui.StyleWarn.Render(" [~] Service already installed. Reinstalling..."))
			_ = service.Uninstall()
		}
		if err := service.Install(exe); err != nil {
			fmt.Fprintf(os.Stderr, "%s  %v\n", tui.StyleErr.Render("[!]"), err)
			os.Exit(1)
		}
		fmt.Println(tui.StyleOK.Render(" [+] Service installed and started"))
		for _, h := range service.ManageHints() {
			fmt.Println(tui.StyleDim.Render("     " + h))
		}
		fmt.Println()
		os.Exit(0)
	}

	// ── One-shot stack scan ───────────────────────────────────────────────────
	if *stackMode {
		c := client.NewClient(*serverURL, *agentID, *serverToken)
		if err := runStack(ctx, c); err != nil {
			fmt.Fprintf(os.Stderr, "%s  stack scan: %v\n", tui.StyleErr.Render("[!]"), err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	slog.Info("satpam-agent starting",
		"version", version,
		"server", *serverURL,
		"interval", *interval,
		"workers", *workers,
		"id", *agentID,
	)

	c := client.NewClient(*serverURL, *agentID, *serverToken)

	runOnce := func() {
		if err := c.Heartbeat(ctx); err != nil {
			slog.Warn("heartbeat failed", "err", err)
		}

		cmds, err := c.FetchCommands(ctx)
		if err != nil {
			slog.Warn("fetch commands failed", "err", err)
		}
		for _, cmd := range cmds {
			slog.Info("executing command", "id", cmd.ID, "type", cmd.Type)
			switch cmd.Type {
			case "scan":
				if err := runScan(ctx, c, *workers); err != nil {
					slog.Error("command scan failed", "id", cmd.ID, "err", err)
				}
			case "stack":
				if err := runStack(ctx, c); err != nil {
					slog.Error("stack scan failed", "id", cmd.ID, "err", err)
				}
			}
			if err := c.AckCommand(ctx, cmd.ID); err != nil {
				slog.Warn("ack command failed", "id", cmd.ID, "err", err)
			}
		}

		if err := runScan(ctx, c, *workers); err != nil {
			slog.Error("scan cycle failed", "err", err)
		}
	}

	runOnce()
	if *interval == 0 {
		return
	}

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		case <-tick.C:
			runOnce()
		}
	}
}

func runScan(ctx context.Context, c *client.Client, workers int) error {
	rs, err := c.FetchRules(ctx)
	if err != nil {
		return err
	}

	// Use platform defaults when server sends no paths.
	if len(rs.ScanConfig.Paths) == 0 {
		rs.ScanConfig.Paths = scanner.DefaultPaths()
	}

	rules, err := yara.ParseRules(rs.YARARules)
	if err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	slog.Info("rules loaded", "count", len(rules), "paths", rs.ScanConfig.Paths,
		"speed_mode", rs.ScanConfig.SpeedMode)

	sc := scanner.NewScanner(rules, rs.ScanConfig, workers)
	findings, err := sc.Scan(ctx)
	if err != nil {
		return err
	}
	slog.Info("scan complete", "findings", len(findings))

	if len(findings) == 0 {
		return nil
	}

	for _, f := range findings {
		slog.Warn("finding",
			"rule", f.RuleName,
			"severity", f.Severity,
			"file", f.FilePath,
			"matched_on", f.MatchedOn,
		)
	}
	return c.ReportFindings(ctx, findings)
}

func runStack(ctx context.Context, c *client.Client) error {
	slog.Info("collecting software inventory")
	inv := inventory.Collect()
	slog.Info("inventory collected", "count", len(inv))

	if err := c.ReportInventory(ctx, inv); err != nil {
		slog.Warn("report inventory failed", "err", err)
	}

	slog.Info("scanning CVEs against inventory")
	cveFindings, err := cve.Scan(ctx, inv)
	if err != nil {
		slog.Warn("CVE scan failed", "err", err)
		return nil
	}
	slog.Info("CVE scan complete", "findings", len(cveFindings))

	if len(cveFindings) == 0 {
		return nil
	}
	for _, f := range cveFindings {
		slog.Warn("CVE finding",
			"cve", f.RuleName,
			"severity", f.Severity,
			"matched_on", f.MatchedOn,
		)
	}
	return c.ReportFindings(ctx, cveFindings)
}

func mustHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown-agent"
	}
	return h
}
