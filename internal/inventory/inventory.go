package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SoftwareEntry is one piece of installed software or a running service.
type SoftwareEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`   // package | service | runtime
	Source  string `json:"source"` // dpkg | rpm | brew | pip | npm | gem | cargo | systemd | launchctl | windows-registry | windows-service | system
	Path    string `json:"path,omitempty"`
}

// Collect returns all detectable software and services on the current machine.
func Collect() []SoftwareEntry {
	switch runtime.GOOS {
	case "linux":
		return dedup(append(append(append(append(append(append(append(
			dpkgPackages(),
			rpmPackages()...),
			pipPackages()...),
			npmPackages()...),
			gemPackages()...),
			cargoPackages()...),
			systemdServices()...),
			knownBinaries()...),
		)
	case "darwin":
		return dedup(append(append(append(append(append(
			brewPackages(),
			pipPackages()...),
			npmPackages()...),
			gemPackages()...),
			launchctlServices()...),
			knownBinaries()...),
		)
	case "windows":
		return dedup(append(append(append(append(append(
			windowsRegistryPackages(),
			windowsServices()...),
			pipPackages()...),
			npmPackages()...),
			knownBinaries()...),
			gemPackages()...),
		)
	default:
		return dedup(knownBinaries())
	}
}

// ── Linux ─────────────────────────────────────────────────────────────────────

func dpkgPackages() []SoftwareEntry {
	out, err := runCmd(20*time.Second, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) == 2 && parts[0] != "" {
			entries = append(entries, SoftwareEntry{
				Name: parts[0], Version: strings.TrimSpace(parts[1]),
				Type: "package", Source: "dpkg",
			})
		}
	}
	return entries
}

func rpmPackages() []SoftwareEntry {
	out, err := runCmd(20*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) == 2 && parts[0] != "" {
			entries = append(entries, SoftwareEntry{
				Name: parts[0], Version: strings.TrimSpace(parts[1]),
				Type: "package", Source: "rpm",
			})
		}
	}
	return entries
}

func systemdServices() []SoftwareEntry {
	out, err := runCmd(10*time.Second,
		"systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		entries = append(entries, SoftwareEntry{
			Name: name, Type: "service", Source: "systemd",
		})
	}
	return entries
}

// ── macOS ─────────────────────────────────────────────────────────────────────

func brewPackages() []SoftwareEntry {
	out, err := runCmd(30*time.Second, "brew", "list", "--versions")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 {
			entries = append(entries, SoftwareEntry{
				Name: parts[0], Version: parts[len(parts)-1],
				Type: "package", Source: "brew",
			})
		}
	}
	return entries
}

func launchctlServices() []SoftwareEntry {
	out, err := runCmd(10*time.Second, "launchctl", "list")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Scan() // skip header
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 3 {
			continue
		}
		label := parts[2]
		if strings.HasPrefix(label, "com.apple.") || label == "-" {
			continue
		}
		entries = append(entries, SoftwareEntry{
			Name: label, Type: "service", Source: "launchctl",
		})
	}
	return entries
}

// ── Windows ───────────────────────────────────────────────────────────────────

func windowsRegistryPackages() []SoftwareEntry {
	script := `$keys = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
		'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
	);
	$keys | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
		Where-Object { $_.DisplayName -ne $null } |
		Select-Object DisplayName,DisplayVersion |
		ConvertTo-Json -Compress`
	out, err := runCmd(30*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil
	}
	var raw []struct {
		Name    string `json:"DisplayName"`
		Version string `json:"DisplayVersion"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		// single object
		var single struct {
			Name    string `json:"DisplayName"`
			Version string `json:"DisplayVersion"`
		}
		if err2 := json.Unmarshal([]byte(out), &single); err2 == nil {
			raw = append(raw, single)
		}
	}
	var entries []SoftwareEntry
	for _, r := range raw {
		if r.Name == "" {
			continue
		}
		entries = append(entries, SoftwareEntry{
			Name: r.Name, Version: r.Version, Type: "package", Source: "windows-registry",
		})
	}
	return entries
}

func windowsServices() []SoftwareEntry {
	script := `Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | ConvertTo-Json -Compress`
	out, err := runCmd(20*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil
	}
	var raw []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		var single struct {
			Name        string `json:"Name"`
			DisplayName string `json:"DisplayName"`
		}
		if err2 := json.Unmarshal([]byte(out), &single); err2 == nil {
			raw = append(raw, single)
		}
	}
	var entries []SoftwareEntry
	for _, s := range raw {
		entries = append(entries, SoftwareEntry{
			Name: s.Name, Type: "service", Source: "windows-service",
		})
	}
	return entries
}

// ── Cross-platform collectors ─────────────────────────────────────────────────

func pipPackages() []SoftwareEntry {
	pip := "pip3"
	if runtime.GOOS == "windows" {
		pip = "pip"
	}
	out, err := runCmd(30*time.Second, pip, "list", "--format=columns")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Scan() // Package  Version
	sc.Scan() // -------  -------
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 {
			entries = append(entries, SoftwareEntry{
				Name: parts[0], Version: parts[1], Type: "package", Source: "pip",
			})
		}
	}
	return entries
}

func npmPackages() []SoftwareEntry {
	out, err := runCmd(30*time.Second, "npm", "list", "-g", "--depth=0", "--json")
	if err != nil {
		return nil
	}
	var result struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal([]byte(out), &result) != nil {
		return nil
	}
	var entries []SoftwareEntry
	for name, dep := range result.Dependencies {
		entries = append(entries, SoftwareEntry{
			Name: name, Version: dep.Version, Type: "package", Source: "npm",
		})
	}
	return entries
}

func gemPackages() []SoftwareEntry {
	out, err := runCmd(30*time.Second, "gem", "list", "--local")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		// format: name (v1, v2, ...)
		idx := strings.Index(line, " (")
		if idx < 0 {
			continue
		}
		name := line[:idx]
		verBlock := strings.Trim(line[idx+2:], ")")
		version := strings.TrimSpace(strings.SplitN(verBlock, ",", 2)[0])
		entries = append(entries, SoftwareEntry{
			Name: name, Version: version, Type: "package", Source: "gem",
		})
	}
	return entries
}

func cargoPackages() []SoftwareEntry {
	out, err := runCmd(30*time.Second, "cargo", "install", "--list")
	if err != nil {
		return nil
	}
	var entries []SoftwareEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, " ") {
			continue
		}
		// format: "crate-name v1.2.3:"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			version := strings.TrimSuffix(strings.TrimPrefix(parts[1], "v"), ":")
			entries = append(entries, SoftwareEntry{
				Name: name, Version: version, Type: "package", Source: "cargo",
			})
		}
	}
	return entries
}

// knownBinaries probes common server/runtime binaries that may not appear in
// package managers (e.g. compiled from source, Docker images, etc.).
var wellKnownBinaries = []string{
	"nginx", "apache2", "httpd", "caddy", "traefik",
	"mysqld", "mysql", "postgres", "mongod", "redis-server",
	"elasticsearch", "opensearch",
	"python3", "python", "ruby", "node", "java", "php",
	"go", "dotnet", "rustc",
	"docker", "containerd", "kubectl", "helm",
	"sshd", "openssl", "curl", "wget", "git",
}

func knownBinaries() []SoftwareEntry {
	var entries []SoftwareEntry
	for _, bin := range wellKnownBinaries {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		version := binaryVersion(bin)
		entries = append(entries, SoftwareEntry{
			Name: bin, Version: version, Type: "runtime", Source: "system", Path: path,
		})
	}
	return entries
}

func binaryVersion(bin string) string {
	for _, flag := range []string{"--version", "-version", "version"} {
		out, err := runCmd(5*time.Second, bin, flag)
		if err != nil {
			continue
		}
		line := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
		if line == "" {
			continue
		}
		if len(line) > 100 {
			line = line[:100]
		}
		return line
	}
	return ""
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func dedup(entries []SoftwareEntry) []SoftwareEntry {
	seen := make(map[string]bool, len(entries))
	out := make([]SoftwareEntry, 0, len(entries))
	for _, e := range entries {
		key := e.Source + ":" + strings.ToLower(e.Name)
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}
