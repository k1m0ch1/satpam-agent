package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patra/satpam-agent/internal/client"
	"github.com/patra/satpam-agent/internal/config"
	"github.com/patra/satpam-agent/internal/scanner"
	"github.com/patra/satpam-agent/internal/setup"
	"github.com/patra/satpam-agent/internal/yara"
)

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

	// ── Load saved config as flag defaults (CLI flags always win) ─────────
	serverDef   := "http://localhost:8080"
	agentIDDef  := mustHostname()
	intervalDef := 5 * time.Minute
	workersDef  := 4

	if cfg, err := config.Load(); err == nil {
		serverDef = cfg.ServerURL
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

	serverURL := flag.String("server", serverDef, "satpam-server base URL")
	interval  := flag.Duration("interval", intervalDef, "scan interval (0 = run once and exit)")
	workers   := flag.Int("workers", workersDef, "parallel scan workers")
	agentID   := flag.String("id", agentIDDef, "agent identifier sent with findings")
	flag.Parse()

	slog.Info("satpam-agent starting",
		"server", *serverURL,
		"interval", *interval,
		"workers", *workers,
		"id", *agentID,
	)

	c := client.NewClient(*serverURL, *agentID)

	runOnce := func() {
		// 1. Heartbeat — tell the server we're alive.
		if err := c.Heartbeat(ctx); err != nil {
			slog.Warn("heartbeat failed", "err", err)
		}

		// 2. Check for pending commands; execute each one immediately.
		cmds, err := c.FetchCommands(ctx)
		if err != nil {
			slog.Warn("fetch commands failed", "err", err)
		}
		for _, cmd := range cmds {
			slog.Info("executing command", "id", cmd.ID, "type", cmd.Type)
			if cmd.Type == "scan" {
				if err := runScan(ctx, c, *workers); err != nil {
					slog.Error("command scan failed", "id", cmd.ID, "err", err)
				}
			}
			if err := c.AckCommand(ctx, cmd.ID); err != nil {
				slog.Warn("ack command failed", "id", cmd.ID, "err", err)
			}
		}

		// 3. Regular scheduled scan (always runs on interval).
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

	rules, err := yara.ParseRules(rs.YARARules)
	if err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	slog.Info("rules loaded", "count", len(rules), "paths", rs.ScanConfig.Paths)

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

func mustHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown-agent"
	}
	return h
}
