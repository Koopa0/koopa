package cmd

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CLISession provides a test helper for CLI interactive testing
// It replaces time.Sleep() with synchronous output waiting using ExpectString()
type CLISession struct {
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
	outputBuffer strings.Builder
	outputMutex  sync.RWMutex
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewCLISession creates a new CLI test session
// It starts goroutines to capture stdout and stderr
func NewCLISession(stdin io.WriteCloser, stdout, stderr io.ReadCloser) *CLISession {
	ctx, cancel := context.WithCancel(context.Background())
	session := &CLISession{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start output capture goroutines
	go session.captureOutput(stdout, "stdout")
	go session.captureOutput(stderr, "stderr")

	return session
}

// captureOutput continuously reads from a reader and stores in buffer
func (s *CLISession) captureOutput(reader io.Reader, label string) {
	if reader == nil {
		return
	}
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			s.outputMutex.Lock()
			s.outputBuffer.Write(buf[:n])
			s.outputMutex.Unlock()
		}

		if err != nil {
			if err != io.EOF {
				// Log error if needed, or just exit loop
			}
			return
		}

		// Check for context cancellation
		select {
		case <-s.ctx.Done():
			return
		default:
			// Continue capturing
		}
	}
}

// SendLine sends a line of input to the CLI
func (s *CLISession) SendLine(input string) error {
	_, err := fmt.Fprintf(s.stdin, "%s\n", input)
	if err != nil {
		return fmt.Errorf("failed to send line: %w", err)
	}
	return nil
}

// ExpectString waits for the output to contain the expected string
// Returns error if timeout is reached before the string appears
func (s *CLISession) ExpectString(expected string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			s.outputMutex.RLock()
			currentOutput := s.outputBuffer.String()
			s.outputMutex.RUnlock()
			return fmt.Errorf("timeout waiting for %q\nGot output:\n%s", expected, currentOutput)

		case <-ticker.C:
			s.outputMutex.RLock()
			output := s.outputBuffer.String()
			s.outputMutex.RUnlock()

			if strings.Contains(output, expected) {
				return nil
			}

		case <-s.ctx.Done():
			return fmt.Errorf("session cancelled")
		}
	}
}

// ExpectRegex waits for the output to match the given regex pattern
func (s *CLISession) ExpectRegex(pattern string, timeout time.Duration) ([]string, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			s.outputMutex.RLock()
			currentOutput := s.outputBuffer.String()
			s.outputMutex.RUnlock()
			return nil, fmt.Errorf("timeout waiting for pattern %q\nGot output:\n%s", pattern, currentOutput)

		case <-ticker.C:
			s.outputMutex.RLock()
			output := s.outputBuffer.String()
			s.outputMutex.RUnlock()

			if matches := regex.FindStringSubmatch(output); matches != nil {
				return matches, nil
			}

		case <-s.ctx.Done():
			return nil, fmt.Errorf("session cancelled")
		}
	}
}

// ExpectPrompt waits for the CLI prompt ("> ")
func (s *CLISession) ExpectPrompt(timeout time.Duration) error {
	return s.ExpectString("> ", timeout)
}

// GetOutput returns the current captured output
func (s *CLISession) GetOutput() string {
	s.outputMutex.RLock()
	defer s.outputMutex.RUnlock()
	return s.outputBuffer.String()
}

// Close closes the session and cleans up resources
func (s *CLISession) Close() error {
	s.cancel()
	close(s.done)

	if err := s.stdin.Close(); err != nil {
		return err
	}

	return nil
}

// WaitForExit waits for the CLI to exit (useful after /exit command)
func (s *CLISession) WaitForExit(timeout time.Duration) error {
	deadline := time.After(timeout)
	select {
	case <-s.done:
		return nil
	case <-deadline:
		return fmt.Errorf("timeout waiting for CLI to exit")
	}
}
