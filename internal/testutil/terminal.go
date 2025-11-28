package testutil

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

// Terminal provides a test helper for CLI interactive testing.
// It captures stdout/stderr and provides expect-style synchronous waiting.
type Terminal struct {
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
	outputBuffer strings.Builder
	outputMutex  sync.RWMutex
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// NewTerminal creates a new terminal test helper.
// It starts goroutines to capture stdout and stderr.
func NewTerminal(stdin io.WriteCloser, stdout, stderr io.ReadCloser) (*Terminal, error) {
	if stdin == nil {
		return nil, errors.New("stdin cannot be nil")
	}

	// Prevent data race: stdout and stderr must not be the same pipe
	if stdout != nil && stderr != nil && stdout == stderr {
		return nil, errors.New("stdout and stderr must be distinct objects to avoid data races")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &Terminal{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}

	if stdout != nil {
		t.wg.Add(1)
		go t.captureOutput(stdout, "stdout")
	}
	if stderr != nil {
		t.wg.Add(1)
		go t.captureOutput(stderr, "stderr")
	}

	return t, nil
}

func (t *Terminal) captureOutput(reader io.Reader, label string) {
	defer t.wg.Done()

	if reader == nil {
		return
	}
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			t.outputMutex.Lock()
			t.outputBuffer.Write(buf[:n])
			t.outputMutex.Unlock()
		}

		if err != nil {
			if err != io.EOF {
				log.Printf("captureOutput[%s]: read error: %v", label, err)
			}
			return
		}

		select {
		case <-t.ctx.Done():
			return
		default:
		}
	}
}

// Send sends input without newline.
func (t *Terminal) Send(input string) error {
	_, err := fmt.Fprint(t.stdin, input)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}
	return nil
}

// SendLine sends a line of input (with newline).
func (t *Terminal) SendLine(input string) error {
	_, err := fmt.Fprintf(t.stdin, "%s\n", input)
	if err != nil {
		return fmt.Errorf("failed to send line: %w", err)
	}
	return nil
}

// ExpectString waits for the output to contain the expected string.
func (t *Terminal) ExpectString(expected string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.outputMutex.RLock()
			output := t.outputBuffer.String()
			t.outputMutex.RUnlock()
			return fmt.Errorf("timeout waiting for %q\nGot output:\n%s", expected, output)

		case <-ticker.C:
			t.outputMutex.RLock()
			output := t.outputBuffer.String()
			t.outputMutex.RUnlock()

			if strings.Contains(output, expected) {
				return nil
			}

		case <-t.ctx.Done():
			return fmt.Errorf("terminal closed")
		}
	}
}

// ExpectRegex waits for the output to match the given regex pattern.
func (t *Terminal) ExpectRegex(pattern string, timeout time.Duration) ([]string, error) {
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
			t.outputMutex.RLock()
			output := t.outputBuffer.String()
			t.outputMutex.RUnlock()
			return nil, fmt.Errorf("timeout waiting for pattern %q\nGot output:\n%s", pattern, output)

		case <-ticker.C:
			t.outputMutex.RLock()
			output := t.outputBuffer.String()
			t.outputMutex.RUnlock()

			if matches := regex.FindStringSubmatch(output); matches != nil {
				return matches, nil
			}

		case <-t.ctx.Done():
			return nil, fmt.Errorf("terminal closed")
		}
	}
}

// ExpectPrompt waits for the CLI prompt ("> ").
func (t *Terminal) ExpectPrompt(timeout time.Duration) error {
	return t.ExpectString("> ", timeout)
}

// Output returns the current captured output.
func (t *Terminal) Output() string {
	t.outputMutex.RLock()
	defer t.outputMutex.RUnlock()
	return t.outputBuffer.String()
}

// Close closes the terminal and cleans up resources.
func (t *Terminal) Close() error {
	t.cancel()
	close(t.done)

	var errs []error

	if t.stdin != nil {
		if err := t.stdin.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stdin: %w", err))
		}
	}

	if t.stdout != nil {
		if err := t.stdout.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stdout: %w", err))
		}
	}

	if t.stderr != nil {
		if err := t.stderr.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing stderr: %w", err))
		}
	}

	t.wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// WaitExit waits for the CLI to exit.
func (t *Terminal) WaitExit(timeout time.Duration) error {
	deadline := time.After(timeout)
	select {
	case <-t.done:
		return nil
	case <-deadline:
		return fmt.Errorf("timeout waiting for exit")
	}
}
