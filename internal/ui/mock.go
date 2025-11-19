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

func (m *Mock) Print(a ...any) {
	fmt.Fprint(&m.Output, a...)
}

func (m *Mock) Println(a ...any) {
	fmt.Fprintln(&m.Output, a...)
}

func (m *Mock) Printf(format string, a ...any) {
	fmt.Fprintf(&m.Output, format, a...)
}

func (m *Mock) Scan() bool {
	if m.inputIndex >= len(m.inputs) {
		return false
	}
	m.inputIndex++
	return true
}

func (m *Mock) Text() string {
	if m.inputIndex-1 < 0 || m.inputIndex-1 >= len(m.inputs) {
		return ""
	}
	return m.inputs[m.inputIndex-1]
}

func (m *Mock) Confirm(prompt string) (bool, error) {
	m.Print(prompt + " [y/n]: ")

	// Check for predefined response
	for k, v := range m.confirmResp {
		if strings.Contains(prompt, k) {
			if v {
				m.Println("y")
				return true, nil
			} else {
				m.Println("n")
				return false, nil
			}
		}
	}

	// Default to yes if not specified (for simple tests)
	m.Println("y")
	return true, nil
}

func (m *Mock) Stream(content string) {
	m.Print(content)
}
