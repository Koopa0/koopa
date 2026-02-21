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
	defaultStateDir = ".koopa"
	stateFile       = "current_session"
	lockTimeout     = 5 * time.Second // Maximum time to wait for lock
	lockFileName    = "current_session.lock"
)

// resolveStateDir returns the state directory path.
// If overrideDir is non-empty, it is used directly (for testing or custom config).
// Otherwise falls back to ~/.koopa (production default).
func resolveStateDir(overrideDir string) (string, error) {
	if overrideDir != "" {
		return overrideDir, nil
	}

	// Production: use ~/.koopa
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}

	return filepath.Join(homeDir, defaultStateDir), nil
}

// stateFilePath returns the full path to the current session state file.
// Creates the state directory if it doesn't exist.
func stateFilePath(overrideDir string) (string, error) {
	stateDirPath, err := resolveStateDir(overrideDir)
	if err != nil {
		return "", err
	}

	// Ensure state directory exists
	if err := os.MkdirAll(stateDirPath, 0o750); err != nil {
		return "", fmt.Errorf("creating state directory: %w", err)
	}

	return filepath.Join(stateDirPath, stateFile), nil
}

// LoadCurrentSessionID loads the currently active session ID from local state file.
//
// The stateDir parameter overrides the default ~/.koopa directory.
// Pass empty string for production default, or a temp directory for testing.
//
// Returns (nil, nil) if state file doesn't exist - this is not an error.
func LoadCurrentSessionID(stateDir string) (*uuid.UUID, error) {
	filePath, err := stateFilePath(stateDir)
	if err != nil {
		return nil, err
	}

	// Acquire file lock to prevent concurrent writes
	lock, err := acquireStateLock(stateDir)
	if err != nil {
		return nil, fmt.Errorf("acquiring lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	// #nosec G304 -- filePath is constructed internally via stateFilePath() to ~/.koopa/current_session, not from user input
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No current session is not an error
		}
		return nil, fmt.Errorf("reading state file: %w", err)
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

// cleanupOrphanedTempFiles removes any stale .tmp files from previous crashed sessions.
func cleanupOrphanedTempFiles(stateDir string) error {
	stateDirPath, err := resolveStateDir(stateDir)
	if err != nil {
		return fmt.Errorf("getting state directory: %w", err)
	}

	pattern := filepath.Join(stateDirPath, "*.tmp")
	tmpFiles, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("finding temp files: %w", err)
	}

	for _, tmpFile := range tmpFiles {
		_ = os.Remove(tmpFile)
	}

	return nil
}

// SaveCurrentSessionID saves the current session ID to local state file.
//
// Uses atomic write (temp file + rename) to ensure file is never partially written.
// The stateDir parameter overrides the default ~/.koopa directory.
func SaveCurrentSessionID(stateDir string, sessionID uuid.UUID) error {
	filePath, err := stateFilePath(stateDir)
	if err != nil {
		return fmt.Errorf("saving session: %w", err)
	}

	lock, err := acquireStateLock(stateDir)
	if err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	_ = cleanupOrphanedTempFiles(stateDir)

	tmpFile := filePath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(sessionID.String()), 0o600); err != nil {
		return fmt.Errorf("writing temp state file: %w", err)
	}

	if err := os.Rename(tmpFile, filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("updating state file: %w", err)
	}

	return nil
}

// ClearCurrentSessionID removes the current session state file.
// Idempotent - calling when no current session exists is not an error.
// The stateDir parameter overrides the default ~/.koopa directory.
func ClearCurrentSessionID(stateDir string) error {
	filePath, err := stateFilePath(stateDir)
	if err != nil {
		return fmt.Errorf("clearing session: %w", err)
	}

	lock, err := acquireStateLock(stateDir)
	if err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	err = os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing state file: %w", err)
	}

	return nil
}

// acquireStateLock acquires an exclusive lock on the state file.
func acquireStateLock(stateDir string) (*flock.Flock, error) {
	stateDirPath, err := resolveStateDir(stateDir)
	if err != nil {
		return nil, err
	}

	if mkdirErr := os.MkdirAll(stateDirPath, 0o750); mkdirErr != nil {
		return nil, fmt.Errorf("creating state directory: %w", mkdirErr)
	}

	lockPath := filepath.Join(stateDirPath, lockFileName)
	lock := flock.New(lockPath)

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("acquiring lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("timeout waiting for file lock after %v", lockTimeout)
	}

	return lock, nil
}
