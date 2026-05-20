package service

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// Install installs and starts the agent as a background service.
//   - Linux  → systemd unit  (system if root, user otherwise)
//   - macOS  → LaunchAgent   (~/.Library/LaunchAgents/)
//   - Windows → Scheduled Task (runs at logon via Task Scheduler)
func Install(exePath string) error {
	switch runtime.GOOS {
	case "linux":
		return installSystemd(exePath)
	case "darwin":
		return installLaunchd(exePath)
	case "windows":
		return installWindows(exePath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall stops and removes the background service.
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallSystemd()
	case "darwin":
		return uninstallLaunchd()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsInstalled reports whether the service is currently installed.
func IsInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		return isInstalledSystemd()
	case "darwin":
		return isInstalledLaunchd()
	case "windows":
		return isInstalledWindows()
	default:
		return false
	}
}

// Description returns a short platform-specific description shown in the wizard.
func Description() string {
	switch runtime.GOOS {
	case "linux":
		if os.Getuid() == 0 {
			return "Installs a systemd system unit. Starts on boot, auto-restarts on crash."
		}
		return "Installs a systemd user unit. Starts at login, auto-restarts on crash."
	case "darwin":
		return "Installs a launchd LaunchAgent. Starts at login, auto-restarts on crash."
	case "windows":
		return "Registers a Task Scheduler task. Starts at logon, restarts on failure."
	default:
		return "Run the agent as a background service."
	}
}

// ManageHints returns lines of useful management commands after install.
func ManageHints() []string {
	switch runtime.GOOS {
	case "linux":
		if os.Getuid() == 0 {
			return []string{
				"Status : systemctl status satpam-agent",
				"Logs   : journalctl -u satpam-agent -f",
				"Stop   : systemctl stop satpam-agent",
			}
		}
		return []string{
			"Status : systemctl --user status satpam-agent",
			"Logs   : journalctl --user -u satpam-agent -f",
			"Stop   : systemctl --user stop satpam-agent",
		}
	case "darwin":
		logPath, _ := darwinLogPath()
		return []string{
			"Status : launchctl list | grep satpam",
			"Logs   : tail -f " + logPath,
			"Stop   : launchctl unload ~/Library/LaunchAgents/com.satpam.agent.plist",
		}
	case "windows":
		return []string{
			"Status : Get-ScheduledTask -TaskName SatpamAgent",
			"Stop   : Stop-ScheduledTask -TaskName SatpamAgent",
			"Logs   : %APPDATA%\\satpam-agent\\satpam-agent.log",
		}
	default:
		return nil
	}
}

// ── Linux / systemd ──────────────────────────────────────────────────────────

var systemdUnitTmpl = template.Must(template.New("unit").Parse(
	`[Unit]
Description=Satpam Security Agent
Documentation=https://github.com/k1m0ch1/satpam-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.ExePath}}
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=satpam-agent

[Install]
WantedBy=multi-user.target
`))

func systemdUnitPath() string {
	if os.Getuid() == 0 {
		return "/etc/systemd/system/satpam-agent.service"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "satpam-agent.service")
}

func systemdFlags() []string {
	if os.Getuid() != 0 {
		return []string{"--user"}
	}
	return nil
}

func systemctl(args ...string) error {
	all := append(systemdFlags(), args...)
	out, err := exec.Command("systemctl", all...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w\n%s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func installSystemd(exe string) error {
	var buf bytes.Buffer
	if err := systemdUnitTmpl.Execute(&buf, struct{ ExePath string }{exe}); err != nil {
		return err
	}
	unitPath := systemdUnitPath()
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return fmt.Errorf("create unit dir: %w", err)
	}
	if err := os.WriteFile(unitPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	for _, step := range [][]string{
		{"daemon-reload"},
		{"enable", "satpam-agent"},
		{"start", "satpam-agent"},
	} {
		if err := systemctl(step...); err != nil {
			return err
		}
	}
	return nil
}

func uninstallSystemd() error {
	systemctl("stop", "satpam-agent")    // best-effort
	systemctl("disable", "satpam-agent") // best-effort
	_ = os.Remove(systemdUnitPath())
	systemctl("daemon-reload")
	return nil
}

func isInstalledSystemd() bool {
	_, err := os.Stat(systemdUnitPath())
	return err == nil
}

// ── macOS / launchd ──────────────────────────────────────────────────────────

const darwinLabel = "com.satpam.agent"

var launchdPlistTmpl = template.Must(template.New("plist").Parse(
	`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.satpam.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.ExePath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogPath}}</string>
    <key>StandardErrorPath</key>
    <string>{{.LogPath}}</string>
</dict>
</plist>
`))

func darwinPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", darwinLabel+".plist"), nil
}

func darwinLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "satpam-agent.log"), nil
}

func installLaunchd(exe string) error {
	plistPath, err := darwinPlistPath()
	if err != nil {
		return err
	}
	logPath, err := darwinLogPath()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := launchdPlistTmpl.Execute(&buf, struct{ ExePath, LogPath string }{exe, logPath}); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}
	if err := os.WriteFile(plistPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Unload first in case it was previously loaded, then load fresh.
	exec.Command("launchctl", "unload", plistPath).Run()
	out, err := exec.Command("launchctl", "load", "-w", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

func uninstallLaunchd() error {
	plistPath, err := darwinPlistPath()
	if err != nil {
		return err
	}
	exec.Command("launchctl", "unload", plistPath).Run()
	return os.Remove(plistPath)
}

func isInstalledLaunchd() bool {
	p, err := darwinPlistPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// ── Windows / Task Scheduler ─────────────────────────────────────────────────

const windowsTaskName = "SatpamAgent"

func installWindows(exe string) error {
	// Escape single quotes for PowerShell string literals.
	escaped := strings.ReplaceAll(exe, "'", "''")

	// Register a task that runs at logon for the current user.
	// -ExecutionTimeLimit 0 means no timeout.
	// RestartInterval/RestartCount auto-restart on crash.
	script := fmt.Sprintf(
		`$a = New-ScheduledTaskAction -Execute '%s';`+
			`$t = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME;`+
			`$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3;`+
			`Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings $s -Force | Out-Null`,
		escaped, windowsTaskName,
	)
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", script,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("register task: %w\n%s", err, bytes.TrimSpace(out))
	}

	// Start immediately (non-fatal — it will start on next logon if this fails).
	exec.Command("schtasks", "/run", "/tn", windowsTaskName).Run()
	return nil
}

func uninstallWindows() error {
	exec.Command("schtasks", "/end", "/tn", windowsTaskName).Run()
	out, err := exec.Command("schtasks", "/delete", "/tn", windowsTaskName, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete task: %w\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

func isInstalledWindows() bool {
	return exec.Command("schtasks", "/query", "/tn", windowsTaskName).Run() == nil
}
