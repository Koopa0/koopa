package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
)

const (
	stateDir     = ".koopa"
	stateFile    = "current_session"
	lockTimeout  = 5 * time.Second // Maximum time to wait for lock
	lockFileName = "current_session.lock"
)

// getStateDirPath returns the state directory path.
// Checks KOOPA_STATE_DIR environment variable first (for testing),
// then falls back to ~/.koopa (for production).
func getStateDirPath() (string, error) {
	// Check for test override
	if testDir := os.Getenv("KOOPA_STATE_DIR"); testDir != "" {
		return testDir, nil
	}

	// Production: use ~/.koopa
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, stateDir), nil
}

// getStateFilePath returns the full path to the current session state file.
// Creates the state directory (~/.koopa) if it doesn't exist.
//
// For testing, you can override the state directory by setting KOOPA_STATE_DIR
// environment variable to a temporary directory (e.g., t.TempDir()).
//
// Returns:
//   - string: Path to ~/.koopa/current_session (or $KOOPA_STATE_DIR/current_session if set)
//   - error: If unable to determine home directory or create state directory
//
// Note: This is a private function as it's only used within the session package.
func getStateFilePath() (string, error) {
	stateDirPath, err := getStateDirPath()
	if err != nil {
		return "", err
	}

	// Ensure state directory exists
	if err := os.MkdirAll(stateDirPath, 0o755); err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}

	return filepath.Join(stateDirPath, stateFile), nil
}

// LoadCurrentSessionID loads the currently active session ID from local state file.
//
// Acquires shared file lock to allow concurrent reads but prevent writes during read.
//
// Returns:
//   - *uuid.UUID: Current session ID (nil if no current session)
//   - error: If state file exists but is malformed or unreadable
//
// Note: Returns (nil, nil) if state file doesn't exist - this is not an error.
func LoadCurrentSessionID() (*uuid.UUID, error) {
	filePath, err := getStateFilePath()
	if err != nil {
		return nil, err
	}

	// Acquire file lock to prevent concurrent writes
	lock, err := acquireStateLock()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No current session is not an error
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	sessionIDStr := strings.TrimSpace(string(data))
	if sessionIDStr == "" {
		return nil, nil
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID in state file: %w", err)
	}

	return &sessionID, nil
}

// SaveCurrentSessionID saves the current session ID to local state file.
//
// Uses atomic write (temp file + rename) to ensure file is never partially written.
// Acquires exclusive file lock to prevent concurrent access.
//
// Parameters:
//   - sessionID: UUID of the session to mark as current
//
// Returns:
//   - error: If unable to write state file
func SaveCurrentSessionID(sessionID uuid.UUID) error {
	filePath, err := getStateFilePath()
	if err != nil {
		return err
	}

	// Acquire file lock to prevent concurrent access
	lock, err := acquireStateLock()
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	// Write to temporary file first (atomic write pattern)
	tmpFile := filePath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(sessionID.String()), 0o644); err != nil {
		return fmt.Errorf("failed to write temp state file: %w", err)
	}

	// Atomically rename temp file to final file
	if err := os.Rename(tmpFile, filePath); err != nil {
		// Clean up temp file on error
		os.Remove(tmpFile)
		return fmt.Errorf("failed to atomically update state file: %w", err)
	}

	return nil
}

// ClearCurrentSessionID removes the current session state file.
//
// Returns:
//   - error: If unable to remove state file (ignores "file not found" errors)
//
// Note: This is idempotent - calling it when no current session exists is not an error.
func ClearCurrentSessionID() error {
	filePath, err := getStateFilePath()
	if err != nil {
		return err
	}

	// Acquire file lock to prevent concurrent access
	lock, err := acquireStateLock()
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	err = os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove state file: %w", err)
	}

	return nil
}

// acquireStateLock acquires an exclusive lock on the state file.
// Returns a locked flock.Flock instance that should be unlocked by the caller.
func acquireStateLock() (*flock.Flock, error) {
	stateDirPath, err := getStateDirPath()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(stateDirPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	lockPath := filepath.Join(stateDirPath, lockFileName)
	lock := flock.New(lockPath)

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("timeout waiting for file lock after %v", lockTimeout)
	}

	return lock, nil
}
