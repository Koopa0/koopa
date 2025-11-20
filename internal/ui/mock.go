package ui

import (
	"fmt"
	"strings"
)

// Mock implements the IO interface for testing.
type Mock struct {
	// Input simulation
	inputs      []string
	inputIndex  int
	confirmResp map[string]bool // Map prompt substring to response

	// Output capture
	Output strings.Builder
}

// NewMock creates a new Mock instance with predefined inputs.
func NewMock(inputs ...string) *Mock {
	return &Mock{
		inputs:      inputs,
		confirmResp: make(map[string]bool),
	}
}

// SetConfirmResponse sets the response for a specific confirmation prompt.
func (m *Mock) SetConfirmResponse(promptSubstring string, response bool) {
	m.confirmResp[promptSubstring] = response
}

// Print outputs values to the mock output buffer
func (m *Mock) Print(a ...any) {
	fmt.Fprint(&m.Output, a...)
}

// Println outputs values with newline to the mock output buffer
func (m *Mock) Println(a ...any) {
	fmt.Fprintln(&m.Output, a...)
}

// Printf outputs formatted string to the mock output buffer
func (m *Mock) Printf(format string, a ...any) {
	fmt.Fprintf(&m.Output, format, a...)
}

// Scan advances to next input and returns true if available
func (m *Mock) Scan() bool {
	if m.inputIndex >= len(m.inputs) {
		return false
	}
	m.inputIndex++
	return true
}

// Text returns the current input text
func (m *Mock) Text() string {
	if m.inputIndex-1 < 0 || m.inputIndex-1 >= len(m.inputs) {
		return ""
	}
	return m.inputs[m.inputIndex-1]
}

// Confirm returns a predefined confirmation response
func (m *Mock) Confirm(prompt string) (bool, error) {
	m.Print(prompt + " [y/n]: ")

	// Check for predefined response
	for k, v := range m.confirmResp {
		if strings.Contains(prompt, k) {
			if v {
				m.Println("y")
				return true, nil
			}
			m.Println("n")
			return false, nil
		}
	}

	// Default to yes if not specified (for simple tests)
	m.Println("y")
	return true, nil
}

// Stream outputs content to the mock output buffer
func (m *Mock) Stream(content string) {
	m.Print(content)
}
