package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var colors = []string{
	"#4285F4", //  Blue
	"#EA4335", //  Red
	"#FBBC04", //  Yellow
	"#34A853", //  Green
}

// KOOPA ASCII art (filled block style - larger and bolder)
var koopaArt = []string{
	"    ██╗  ██╗ ██████╗  ██████╗ ██████╗  █████╗ ",
	"    ██║ ██╔╝██╔═══██╗██╔═══██╗██╔══██╗██╔══██╗",
	"    █████╔╝ ██║   ██║██║   ██║██████╔╝███████║",
	"    ██╔═██╗ ██║   ██║██║   ██║██╔═══╝ ██╔══██║",
	"    ██║  ██╗╚██████╔╝╚██████╔╝██║     ██║  ██║",
	"    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝",
}

// Arrow ASCII art (large ">" shape)
var arrowArt = []string{
	"  ██  ",
	"   ██ ",
	"    ██",
	"   ██ ",
	"  ██  ",
	"      ",
}

// Print displays the KOOPA banner with unified color
func Print() {
	PrintTo(os.Stdout)
}

// PrintTo displays the KOOPA banner to a custom writer
func PrintTo(w io.Writer) {
	_, _ = fmt.Fprintln(w)

	// Unified style with Google Blue
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(colors[0])). // Google Blue
		Bold(true)

	// Render arrow and text side by side
	for i := range len(koopaArt) {
		arrow := style.Render(arrowArt[i])
		text := style.Render(koopaArt[i])
		_, _ = fmt.Fprintln(w, arrow+text)
	}

	_, _ = fmt.Fprintln(w)
}

// PrintWithInfo displays the banner with version and model info
func PrintWithInfo(version, model string) {
	Print()

	// Info style (subtle gray)
	infoStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#808080")).
		Italic(true)

	info := fmt.Sprintf("Version: %s | Model: %s", version, model)
	fmt.Println(infoStyle.Render(info))
	fmt.Println()
}

// GetBannerString returns the banner as a string (for testing)
func GetBannerString() string {
	var sb strings.Builder
	sb.WriteString(">\n")
	for _, line := range koopaArt {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}
