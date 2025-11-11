package banner

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var googleColors = []string{
	"#4285F4", // Google Blue
	"#EA4335", // Google Red
	"#FBBC04", // Google Yellow
	"#34A853", // Google Green
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
	fmt.Println()

	// Unified style with Google Blue
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(googleColors[0])). // Google Blue
		Bold(true)

	// Render arrow and text side by side
	for i := 0; i < len(koopaArt); i++ {
		arrow := style.Render(arrowArt[i])
		text := style.Render(koopaArt[i])
		fmt.Println(arrow + text)
	}

	fmt.Println()
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
