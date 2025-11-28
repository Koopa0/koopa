package security

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Sentinel errors for path validation.
// Use errors.Is() to check these errors.
var (
	// ErrPathOutsideAllowed indicates the path is outside allowed directories.
	ErrPathOutsideAllowed = errors.New("path is outside allowed directories")

	// ErrSymlinkOutsideAllowed indicates a symbolic link points outside allowed directories.
	ErrSymlinkOutsideAllowed = errors.New("symbolic link points outside allowed directories")

	// ErrPathNullByte indicates the path contains a null byte (CWE-626).
	ErrPathNullByte = errors.New("path contains null byte")
)

// Path validates and sanitizes file paths to prevent traversal attacks.
// Used to prevent path traversal attacks (CWE-22).
type Path struct {
	allowedDirs []string
	workDir     string
}

// NewPath creates a new Path validator.
// allowedDirs: list of allowed directories (empty list means only working directory is allowed)
func NewPath(allowedDirs []string) (*Path, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("unable to get working directory: %w", err)
	}

	// Convert all allowed directories to absolute paths
	absAllowedDirs := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve directory %s: %w", dir, err)
		}
		absAllowedDirs = append(absAllowedDirs, absDir)
	}

	return &Path{
		allowedDirs: absAllowedDirs,
		workDir:     workDir,
	}, nil
}

// isPathInAllowedDirs checks if a path is within allowed directories
// Returns true if path is in working directory or any allowed directory
func (v *Path) isPathInAllowedDirs(absPath string) bool {
	// Normalize for exact matching (add trailing separator)
	absPathWithSep := filepath.Clean(absPath) + string(filepath.Separator)
	workDirNorm := filepath.Clean(v.workDir) + string(filepath.Separator)

	// Check working directory first
	if strings.HasPrefix(absPathWithSep, workDirNorm) || absPath == v.workDir {
		return true
	}

	// Check additional allowed directories
	for _, dir := range v.allowedDirs {
		dirNorm := filepath.Clean(dir) + string(filepath.Separator)
		if strings.HasPrefix(absPathWithSep, dirNorm) || absPath == dir {
			return true
		}
	}

	return false
}

// Validate validates and sanitizes a file path.
// Returns a safe absolute path or an error.
//
// SECURITY NOTE - TOCTOU (Time-Of-Check to Time-Of-Use) Limitation:
// This validation checks the path at a specific point in time, but the filesystem
// state can change between validation and actual file access. This is an inherent
// limitation of all filesystem-based security checks and cannot be fully eliminated.
//
// Mitigation strategies in place:
//   - Minimize time window between check and use (caller should use path immediately)
//   - Use atomic operations where possible (os.OpenFile with O_EXCL for creation)
//   - Symlink resolution to prevent link-based attacks
//   - Directory access control (working directory + explicit allow list)
//
// Callers should:
//   - Use the returned path immediately after validation
//   - Avoid storing validated paths for later use
//   - Consider using file descriptors (once opened) for multiple operations
//
// Reference: CWE-367 (Time-of-check Time-of-use Race Condition)
func (v *Path) Validate(path string) (string, error) {
	// 0. Reject null bytes (CWE-626: Null Byte Interaction Error)
	// Null bytes can truncate paths in C-based syscalls, bypassing validation
	if strings.Contains(path, "\x00") {
		slog.Warn("null byte detected in path",
			"path_length", len(path),
			"security_event", "null_byte_injection_attempt")
		return "", fmt.Errorf("%w: invalid path", ErrPathNullByte)
	}

	// 1. Clean the path (remove ../ etc.)
	cleanPath := filepath.Clean(path)

	// 2. Convert to absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// 3. Check if within allowed directories
	if !v.isPathInAllowedDirs(absPath) {
		slog.Warn("path access denied",
			"path", absPath,
			"working_dir", v.workDir,
			"allowed_dirs", v.allowedDirs,
			"security_event", "path_traversal_attempt")
		// Return sentinel error wrapped with generic message
		return "", fmt.Errorf("%w: access denied", ErrPathOutsideAllowed)
	}

	// 4. Resolve symbolic links (prevent bypassing restrictions through symlinks)
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// If file doesn't exist, EvalSymlinks will fail
		// This is acceptable for creating new files
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("unable to resolve symbolic link: %w", err)
		}
		// File doesn't exist, but path is safe
		return absPath, nil
	}

	// 5. Check again if the resolved symlink path is within allowed directories
	if realPath != absPath {
		if !v.isPathInAllowedDirs(realPath) {
			slog.Warn("symlink bypass attempt detected",
				"original_path", absPath,
				"symlink_target", realPath,
				"working_dir", v.workDir,
				"allowed_dirs", v.allowedDirs,
				"security_event", "symlink_traversal_attempt")
			// Return sentinel error wrapped with generic message
			return "", fmt.Errorf("%w: access denied", ErrSymlinkOutsideAllowed)
		}
		absPath = realPath
	}

	return absPath, nil
}

// IsPathSafe quickly checks if a path contains obvious dangerous patterns
// This is an additional layer of protection but should not be relied upon alone
func IsPathSafe(path string) bool {
	// Check for common dangerous patterns
	dangerousPatterns := []string{
		"../",    // Upward traversal
		"..\\",   // Windows upward traversal
		"/etc/",  // System configuration
		"/dev/",  // Device files
		"/proc/", // Process information
		"/sys/",  // System information
		"c:\\",   // Windows system root directory
		"c:/",    // Windows system root directory
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	return true
}

// GetHomeDir safely retrieves the user's home directory
func GetHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to get user home directory: %w", err)
	}
	return home, nil
}
