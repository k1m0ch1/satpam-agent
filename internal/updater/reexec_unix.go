//go:build !windows

package updater

import (
	"os"
	"syscall"
)

// reexec replaces the current process image with the updated binary (Unix only).
func reexec(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
