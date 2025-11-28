package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// Google Blue color for KOOPA branding
const googleBlue = "#4285F4"

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

// Styles contains all lipgloss styles for the TUI.
type Styles struct {
	Banner    lipgloss.Style
	Header    lipgloss.Style
	User      lipgloss.Style
	Assistant lipgloss.Style
	System    lipgloss.Style
	Tips      lipgloss.Style // White color for tips (more visible)
	Error     lipgloss.Style
	Prompt    lipgloss.Style
	Separator lipgloss.Style // Horizontal line separator
	StatusBar lipgloss.Style
}

// DefaultStyles returns the default style configuration.
func DefaultStyles() Styles {
	return Styles{
		Banner:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(googleBlue)),
		Header:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(googleBlue)),
		User:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")),
		Assistant: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")),
		System:    lipgloss.NewStyle().Italic(true).Foreground(lipgloss.Color("240")),
		Tips:      lipgloss.NewStyle().Foreground(lipgloss.Color("255")), // White for visibility
		Error:     lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		Prompt:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")),
		Separator: lipgloss.NewStyle().Foreground(lipgloss.Color("240")), // Gray separator line
		StatusBar: lipgloss.NewStyle().Foreground(lipgloss.Color("250")), // Light gray, no background
	}
}

// RenderBanner returns the KOOPA ASCII art banner as a styled string.
func (s Styles) RenderBanner() string {
	var b strings.Builder
	for i := range koopaArt {
		arrow := s.Banner.Render(arrowArt[i])
		text := s.Banner.Render(koopaArt[i])
		_, _ = b.WriteString(arrow)
		_, _ = b.WriteString(text)
		_, _ = b.WriteString("\n")
	}
	return b.String()
}

// welcomeTips contains getting started tips displayed under the banner.
var welcomeTips = []string{
	"Tips for getting started:",
	"  • Ask questions naturally - Koopa understands context",
	"  • Use /help to see available commands",
	"  • Press Ctrl+C to cancel, Ctrl+D to exit",
	"  • Up/Down arrows navigate command history",
}

// RenderWelcomeTips returns styled welcome tips (white for visibility).
func (s Styles) RenderWelcomeTips() string {
	var b strings.Builder
	for _, tip := range welcomeTips {
		_, _ = b.WriteString(s.Tips.Render(tip))
		_, _ = b.WriteString("\n")
	}
	return b.String()
}
