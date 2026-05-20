package scanner

import (
	"os"
	"runtime"
)

// DefaultPaths returns platform-specific directories to scan when the server
// sends an empty Paths list in ScanConfig.
func DefaultPaths() []string {
	switch runtime.GOOS {
	case "windows":
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users`}
	default: // linux, darwin
		home, _ := os.UserHomeDir()
		seen := map[string]bool{}
		var paths []string
		for _, p := range []string{"/var/www", "/home", home} {
			if p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
		return paths
	}
}
