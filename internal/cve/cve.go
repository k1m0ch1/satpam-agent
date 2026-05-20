// Package cve fetches recent CVE data from https://github.com/CVEProject/cvelistV5
// and matches entries against the local software inventory.
package cve

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/patra/satpam-agent/internal/inventory"
	"github.com/patra/satpam-agent/internal/scanner"
)

const (
	cveRepo  = "CVEProject/cvelistV5"
	cacheTTL = 24 * time.Hour
)

// entry is a flattened, matchable representation of one CVE.
type entry struct {
	ID          string       `json:"id"`
	Product     string       `json:"product"`
	Vendor      string       `json:"vendor"`
	Versions    []cveVersion `json:"versions"`
	Description string       `json:"description"`
	Score       float64      `json:"score"`
	Severity    string       `json:"severity"`
	URL         string       `json:"url"`
}

type cveVersion struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	LessThan        string `json:"lessThan,omitempty"`
	LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
}

// cache is persisted to ~/.satpam-agent/cve_cache.json
type cache struct {
	FetchedAt time.Time `json:"fetched_at"`
	Release   string    `json:"release"`
	Entries   []entry   `json:"entries"`
}

// Scan fetches (or loads cached) CVE data and matches it against the provided
// software inventory. It returns findings formatted for satpam-server.
func Scan(ctx context.Context, software []inventory.SoftwareEntry) ([]scanner.Finding, error) {
	entries, err := loadOrFetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("CVE data unavailable: %w", err)
	}
	slog.Info("CVE entries loaded", "count", len(entries))

	index := buildIndex(entries)
	var findings []scanner.Finding
	for _, sw := range software {
		swNorm := normalizeName(sw.Name)
		for prod, cves := range index {
			if !nameMatch(swNorm, prod) {
				continue
			}
			for _, cv := range cves {
				if !versionAffected(sw.Version, cv.Versions) {
					continue
				}
				loc := sw.Path
				if loc == "" {
					loc = "unknown"
				}
				findings = append(findings, scanner.Finding{
					RuleName:  cv.ID,
					Severity:  cv.Severity,
					FilePath:  loc,
					MatchedOn: fmt.Sprintf("%s %s matches %s (CVSS %.1f)", sw.Name, sw.Version, cv.ID, cv.Score),
					Snippet: fmt.Sprintf(
						"Service: %s | Version installed: %s | Location: %s | CVE: %s | CVSS: %.1f (%s) | Description: %s | Reference: %s",
						sw.Name, sw.Version, loc, cv.ID, cv.Score, cv.Severity, cv.Description, cv.URL,
					),
				})
			}
		}
	}
	return findings, nil
}

// ── Cache ─────────────────────────────────────────────────────────────────────

func cachePath() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, ".satpam-agent", "cve_cache.json")
}

func loadOrFetch(ctx context.Context) ([]entry, error) {
	cp := cachePath()
	if cp != "" {
		if data, err := os.ReadFile(cp); err == nil {
			var c cache
			if json.Unmarshal(data, &c) == nil && time.Since(c.FetchedAt) < cacheTTL {
				slog.Info("CVE cache hit", "release", c.Release, "age", time.Since(c.FetchedAt).Round(time.Minute))
				return c.Entries, nil
			}
		}
	}

	slog.Info("fetching CVE data from CVEProject/cvelistV5")
	rel, assetURL, err := latestDeltaAsset(ctx)
	if err != nil {
		return nil, err
	}
	slog.Info("downloading CVE delta", "release", rel, "url", assetURL)

	entries, err := downloadAndParse(ctx, assetURL)
	if err != nil {
		return nil, err
	}

	if cp != "" {
		c := cache{FetchedAt: time.Now(), Release: rel, Entries: entries}
		if data, merr := json.Marshal(c); merr == nil {
			_ = os.MkdirAll(filepath.Dir(cp), 0o755)
			_ = os.WriteFile(cp, data, 0o600)
		}
	}
	return entries, nil
}

// ── GitHub release fetching ───────────────────────────────────────────────────

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func latestDeltaAsset(ctx context.Context) (tag, url string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", cveRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("GitHub API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}

	for _, a := range rel.Assets {
		if strings.HasPrefix(a.Name, "deltaCves_") && strings.HasSuffix(a.Name, ".zip.gz") {
			return rel.TagName, a.BrowserDownloadURL, nil
		}
	}
	// Fallback: look for any .zip.gz asset (not the full db)
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, ".zip.gz") && !strings.Contains(a.Name, "cvelistV5_") {
			return rel.TagName, a.BrowserDownloadURL, nil
		}
	}
	return "", "", fmt.Errorf("no delta CVE archive found in release %s", rel.TagName)
}

// ── ZIP + gzip download and parsing ──────────────────────────────────────────

func downloadAndParse(ctx context.Context, url string) ([]entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}

	var entries []entry
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || strings.HasSuffix(f.Name, "deltaLog.json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		entries = append(entries, parseCVEJSON(raw)...)
	}
	return entries, nil
}

// ── CVE JSON parsing (schema 5.x) ─────────────────────────────────────────────

type cveRecord struct {
	CVEMetadata struct {
		CVEID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Affected []struct {
				Product  string       `json:"product"`
				Vendor   string       `json:"vendor"`
				Versions []cveVersion `json:"versions"`
			} `json:"affected"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics []struct {
				CVSSV40 *cvssScore `json:"cvssV4_0,omitempty"`
				CVSSV31 *cvssScore `json:"cvssV3_1,omitempty"`
				CVSSV30 *cvssScore `json:"cvssV3_0,omitempty"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

type cvssScore struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func parseCVEJSON(data []byte) []entry {
	var rec cveRecord
	if json.Unmarshal(data, &rec) != nil {
		return nil
	}
	if rec.CVEMetadata.State != "PUBLISHED" {
		return nil
	}

	cveID := rec.CVEMetadata.CVEID
	cna := rec.Containers.CNA

	// Description (English preferred)
	desc := ""
	for _, d := range cna.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(cna.Descriptions) > 0 {
		desc = cna.Descriptions[0].Value
	}
	if len(desc) > 300 {
		desc = desc[:297] + "..."
	}

	// CVSS score (prefer V4 → V3.1 → V3.0)
	score := 0.0
	severity := "UNKNOWN"
	for _, m := range cna.Metrics {
		if m.CVSSV40 != nil {
			score, severity = m.CVSSV40.BaseScore, m.CVSSV40.BaseSeverity
			break
		}
		if m.CVSSV31 != nil {
			score, severity = m.CVSSV31.BaseScore, m.CVSSV31.BaseSeverity
			break
		}
		if m.CVSSV30 != nil {
			score, severity = m.CVSSV30.BaseScore, m.CVSSV30.BaseSeverity
			break
		}
	}
	severity = normalizeSeverity(score, severity)

	// First reference URL
	refURL := ""
	for _, r := range cna.References {
		if r.URL != "" {
			refURL = r.URL
			break
		}
	}
	if refURL == "" {
		refURL = fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cveID)
	}

	var entries []entry
	for _, aff := range cna.Affected {
		if aff.Product == "" {
			continue
		}
		entries = append(entries, entry{
			ID:          cveID,
			Product:     strings.ToLower(aff.Product),
			Vendor:      strings.ToLower(aff.Vendor),
			Versions:    aff.Versions,
			Description: desc,
			Score:       score,
			Severity:    severity,
			URL:         refURL,
		})
	}
	return entries
}

// ── Matching ──────────────────────────────────────────────────────────────────

// buildIndex groups entries by normalized product name for fast lookup.
func buildIndex(entries []entry) map[string][]entry {
	idx := make(map[string][]entry, len(entries))
	for _, e := range entries {
		idx[e.Product] = append(idx[e.Product], e)
	}
	return idx
}

// nameMatch returns true when the software name plausibly matches a CVE product.
func nameMatch(swNorm, prod string) bool {
	if swNorm == prod {
		return true
	}
	// One is a prefix/suffix of the other (handles nginx vs nginx-core, etc.)
	if strings.HasPrefix(swNorm, prod) || strings.HasPrefix(prod, swNorm) {
		return true
	}
	// Check alias map
	if aliases, ok := productAliases[prod]; ok {
		for _, a := range aliases {
			if swNorm == a || strings.HasPrefix(swNorm, a) {
				return true
			}
		}
	}
	return false
}

// productAliases maps CVE product names to common package/binary names.
var productAliases = map[string][]string{
	"apache_http_server": {"apache2", "httpd", "apache"},
	"apache":             {"apache2", "httpd"},
	"nginx":              {"nginx-core", "nginx-full", "nginx-extras", "nginx-light"},
	"postgresql":         {"postgres", "postgresql-14", "postgresql-15", "postgresql-16", "postgresql-17"},
	"mysql":              {"mysql-server", "mysql-client", "mysql-community-server", "mysqld"},
	"python":             {"python3", "python2", "python3.10", "python3.11", "python3.12", "python3.13"},
	"node.js":            {"node", "nodejs"},
	"openssl":            {"libssl1.1", "libssl3", "libssl-dev"},
	"openssh":            {"openssh-server", "openssh-client", "sshd"},
	"redis":              {"redis-server"},
	"mongodb":            {"mongod"},
	"spring_framework":   {"spring-core", "spring"},
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// versionAffected returns true when the installed version falls in any
// "affected" range declared by the CVE. Conservatively returns true when
// version info is absent or unparseable.
func versionAffected(installed string, versions []cveVersion) bool {
	if len(versions) == 0 {
		return true
	}
	installedN := parseVersion(installed)

	for _, v := range versions {
		if v.Status != "affected" {
			continue
		}
		if v.LessThan != "" {
			if semverLess(installedN, parseVersion(v.LessThan)) {
				return true
			}
		} else if v.LessThanOrEqual != "" {
			lt := parseVersion(v.LessThanOrEqual)
			if semverLess(installedN, lt) || installedN == lt {
				return true
			}
		} else if v.Version == "" || v.Version == "0" || v.Version == "*" {
			return true
		} else {
			// Exact version or range base — match if installed starts with it
			if strings.HasPrefix(installed, v.Version) {
				return true
			}
		}
	}
	return false
}

type verTuple [4]int

func parseVersion(v string) verTuple {
	v = strings.TrimPrefix(v, "v")
	// Strip suffixes like "-4ubuntu1", "+dfsg", etc.
	for _, sep := range []string{"-", "+", "~", ":"} {
		if idx := strings.Index(v, sep); idx >= 0 {
			v = v[:idx]
		}
	}
	parts := strings.SplitN(v, ".", 4)
	var t verTuple
	for i, p := range parts {
		if i >= 4 {
			break
		}
		t[i], _ = strconv.Atoi(p)
	}
	return t
}

func semverLess(a, b verTuple) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

func normalizeSeverity(score float64, raw string) string {
	upper := strings.ToUpper(raw)
	switch upper {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return upper
	}
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
