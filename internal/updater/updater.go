package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/patra/satpam-agent/internal/tui"
)

const githubRepo = "k1m0ch1/satpam-agent"

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckAndPrompt checks GitHub for the latest release and handles the update flow.
// It always fetches the latest version. Prompts to update only when local < latest
// and local is not a dev build.
func CheckAndPrompt(ctx context.Context, current string) {
	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	rel, err := fetchLatest(checkCtx)
	if err != nil {
		return // silent fail — don't block startup on network issues
	}

	isDev := current == "dev"
	hasUpdate := isNewer(rel.TagName, current) // latest > current

	switch {
	case isDev:
		// dev build: show latest for reference, skip update prompt
		tui.PrintInfoRow(" + -- -", fmt.Sprintf("Update  : dev build  (latest: %s)", rel.TagName))
		fmt.Println()
		return

	case !hasUpdate:
		// current >= latest: already up to date or newer, nothing to show
		return
	}

	// current < latest: show notification + prompt
	fmt.Println(tui.InfoRow(" + -- -", tui.StyleWarn.Render(
		fmt.Sprintf("Update  : %s  →  %s available!", current, rel.TagName),
	)))
	fmt.Println()

	assetURL, err := findAssetURL(rel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s  auto-update unavailable for %s/%s\n",
			tui.StyleErr.Render("[!]"), runtime.GOOS, runtime.GOARCH)
		return
	}

	var doUpdate bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Update available: %s", rel.TagName)).
				Description(fmt.Sprintf("Replace satpam-agent %s → %s and relaunch?", current, rel.TagName)).
				Affirmative("Yes, update now").
				Negative("Skip").
				Value(&doUpdate),
		),
	).WithTheme(tui.HackerTheme())

	if err := form.Run(); err != nil || !doUpdate {
		fmt.Println()
		return
	}

	fmt.Println()
	if err := applyUpdate(ctx, assetURL); err != nil {
		fmt.Fprintf(os.Stderr, "%s  update failed: %v\n", tui.StyleErr.Render("[!]"), err)
	}
}

func fetchLatest(ctx context.Context) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %d", resp.StatusCode)
	}

	var rel ghRelease
	return &rel, json.NewDecoder(resp.Body).Decode(&rel)
}

func findAssetURL(rel *ghRelease) (string, error) {
	name := fmt.Sprintf("satpam-agent-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no asset for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func applyUpdate(ctx context.Context, url string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("eval symlinks: %w", err)
	}

	tmp := exe + ".new"
	if err := downloadTo(ctx, url, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("download: %w", err)
	}

	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := replaceBinary(exe, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace binary: %w", err)
	}

	fmt.Println(tui.StyleOK.Render(" [+] Update applied. Relaunching..."))
	fmt.Println()
	return reexec(exe)
}

func replaceBinary(exe, tmp string) error {
	if runtime.GOOS == "windows" {
		// Windows: can't overwrite a running .exe, but can rename it
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return fmt.Errorf("rename current: %w", err)
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(old, exe) // restore on failure
			return fmt.Errorf("place new binary: %w", err)
		}
		return nil
	}
	// Unix: atomic rename works even while the binary is running
	return os.Rename(tmp, exe)
}

func downloadTo(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	pr := &progressReader{r: resp.Body, total: resp.ContentLength}
	_, err = io.Copy(f, pr)
	fmt.Println() // newline after progress line
	return err
}

type progressReader struct {
	r     io.Reader
	total int64
	read  int64
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.read += int64(n)
	if p.total > 0 {
		pct := p.read * 100 / p.total
		fmt.Printf("\r %s Downloading... %d%%  ", tui.StyleGreen.Render("[*]"), pct)
	} else {
		fmt.Printf("\r %s Downloading... %s  ", tui.StyleGreen.Render("[*]"), humanBytes(p.read))
	}
	return n, err
}

func humanBytes(b int64) string {
	const kb, mb = 1024, 1024 * 1024
	switch {
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/mb)
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/kb)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func isNewer(latest, current string) bool {
	return semverCmp(latest, current) > 0
}

func semverCmp(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	for i := range pa {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
