package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

var (
	StyleLogo  = lipgloss.NewStyle().Foreground(lipgloss.Color("#E63946")).Bold(true)
	StyleSub   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	StyleGreen = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF41"))
	StyleText  = lipgloss.NewStyle().Foreground(lipgloss.Color("#E2E8F0"))
	StyleDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("#374151"))
	StyleSep   = lipgloss.NewStyle().Foreground(lipgloss.Color("#1E293B"))
	StyleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF41")).Bold(true)
	StyleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Bold(true)
	StyleErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E63946")).Bold(true)
)

// InfoRow renders a Metasploit-style info row:
//
//	prefix =[  content  ]
func InfoRow(prefix, content string) string {
	const w = 50
	pad := w - len(content)
	if pad < 0 {
		pad = 0
	}
	return StyleDim.Render(prefix) +
		StyleGreen.Render("=[") +
		" " + StyleText.Render(content+strings.Repeat(" ", pad)) + " " +
		StyleGreen.Render("]")
}

func PrintInfoRow(prefix, content string) {
	fmt.Println(InfoRow(prefix, content))
}

func Separator() string {
	return StyleSep.Render("  " + strings.Repeat("─", 62))
}

func HackerTheme() *huh.Theme {
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
