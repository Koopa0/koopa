package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	stateDir  = ".koopa"
	stateFile = "current_session"
)

// GetStateFilePath returns the full path to the current session state file.
// Creates the state directory (~/.koopa) if it doesn't exist.
//
// Returns:
//   - string: Path to ~/.koopa/current_session
//   - error: If unable to determine home directory or create state directory
func GetStateFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	stateDirPath := filepath.Join(homeDir, stateDir)
	// Ensure state directory exists
	if err := os.MkdirAll(stateDirPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}

	return filepath.Join(stateDirPath, stateFile), nil
}

// LoadCurrentSessionID loads the currently active session ID from local state file.
//
// Returns:
//   - *uuid.UUID: Current session ID (nil if no current session)
//   - error: If state file exists but is malformed or unreadable
//
// Note: Returns (nil, nil) if state file doesn't exist - this is not an error.
func LoadCurrentSessionID() (*uuid.UUID, error) {
	filePath, err := GetStateFilePath()
	if err != nil {
		return nil, err
	}

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
// Parameters:
//   - sessionID: UUID of the session to mark as current
//
// Returns:
//   - error: If unable to write state file
func SaveCurrentSessionID(sessionID uuid.UUID) error {
	filePath, err := GetStateFilePath()
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, []byte(sessionID.String()), 0644)
	if err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
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
	filePath, err := GetStateFilePath()
	if err != nil {
		return err
	}

	err = os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove state file: %w", err)
	}

	return nil
}
