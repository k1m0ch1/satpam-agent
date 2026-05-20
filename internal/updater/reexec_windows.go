//go:build windows

package updater

import (
	"os"
	"os/exec"
)

// reexec spawns the updated binary and exits the current process (Windows only).
// Windows cannot replace a running .exe in-place, so we rename-and-relaunch instead.
func reexec(exe string) error {
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
