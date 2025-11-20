package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	wg           sync.WaitGroup // Ensures goroutines exit before Close() returns
}

// NewCLISession creates a new CLI test session
// It starts goroutines to capture stdout and stderr
// Returns error if stdin is nil (required parameter)
func NewCLISession(stdin io.WriteCloser, stdout, stderr io.ReadCloser) (*CLISession, error) {
	// Input validation: stdin is required, stdout/stderr are optional
	if stdin == nil {
		return nil, errors.New("stdin cannot be nil")
	}

	// Prevent data race: stdout and stderr must not be the same pipe
	// Two goroutines reading from the same pipe can cause unpredictable behavior
	if stdout != nil && stderr != nil && stdout == stderr {
		return nil, errors.New("stdout and stderr must be distinct objects to avoid data races")
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &CLISession{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start output capture goroutines only if readers are non-nil
	// WaitGroup ensures Close() will wait for these to exit
	if stdout != nil {
		session.wg.Add(1)
		go session.captureOutput(stdout, "stdout")
	}
	if stderr != nil {
		session.wg.Add(1)
		go session.captureOutput(stderr, "stderr")
	}

	return session, nil
}

// captureOutput continuously reads from a reader and stores in buffer
func (s *CLISession) captureOutput(reader io.Reader, label string) {
	defer s.wg.Done() // Signal completion when goroutine exits

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
			// Log non-EOF errors for debugging
			if err != io.EOF {
				log.Printf("captureOutput[%s]: read error: %v", label, err)
			}
			// Exit loop on any error (including EOF)
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
	// Cancel context first to signal goroutines
	s.cancel()
	close(s.done)

	// IMPORTANT: Close all pipes to unblock captureOutput goroutines
	// Closing stdout/stderr will cause Read() to return io.EOF,
	// allowing the goroutines to exit and preventing goroutine leaks
	var errs []error

	if s.stdin != nil {
		if err := s.stdin.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stdin: %w", err))
		}
	}

	if s.stdout != nil {
		if err := s.stdout.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stdout: %w", err))
		}
	}

	if s.stderr != nil {
		if err := s.stderr.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stderr: %w", err))
		}
	}

	// Wait for all captureOutput goroutines to exit
	// This MUST be after closing pipes, because goroutines are blocked on Read()
	// and will only exit after pipes are closed (Read() returns EOF)
	s.wg.Wait()

	// Return combined errors using errors.Join (Go 1.20+)
	// This ensures all cleanup failures are reported, not just the first one
	if len(errs) > 0 {
		return errors.Join(errs...)
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
