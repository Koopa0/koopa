package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathValidator path validator
// Used to prevent path traversal attacks (CWE-22)
type PathValidator struct {
	allowedDirs []string
	workDir     string
}

// NewPathValidator creates a path validator
// allowedDirs: list of allowed directories (empty list means only working directory is allowed)
func NewPathValidator(allowedDirs []string) (*PathValidator, error) {
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

	return &PathValidator{
		allowedDirs: absAllowedDirs,
		workDir:     workDir,
	}, nil
}

// ValidatePath validates and sanitizes a file path
// Returns a safe absolute path or an error
func (v *PathValidator) ValidatePath(path string) (string, error) {
	// 1. Clean the path (remove ../ etc.)
	cleanPath := filepath.Clean(path)

	// 2. Convert to absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// 3. Check if within allowed directories
	allowed := false

	// Normalize directory paths (ensure trailing slash for exact matching)
	workDirNorm := filepath.Clean(v.workDir) + string(filepath.Separator)
	absPathWithSep := filepath.Clean(absPath) + string(filepath.Separator)

	// First check working directory
	if strings.HasPrefix(absPathWithSep, workDirNorm) || absPath == v.workDir {
		allowed = true
	}

	// Then check additional allowed directories
	if !allowed {
		for _, dir := range v.allowedDirs {
			dirNorm := filepath.Clean(dir) + string(filepath.Separator)
			if strings.HasPrefix(absPathWithSep, dirNorm) || absPath == dir {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		return "", fmt.Errorf("access denied: path '%s' is not within allowed directories", absPath)
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
		realPathWithSep := filepath.Clean(realPath) + string(filepath.Separator)
		realAllowed := false

		// Check working directory
		if strings.HasPrefix(realPathWithSep, workDirNorm) || realPath == v.workDir {
			realAllowed = true
		}

		// Check allowed directories
		if !realAllowed {
			for _, dir := range v.allowedDirs {
				dirNorm := filepath.Clean(dir) + string(filepath.Separator)
				if strings.HasPrefix(realPathWithSep, dirNorm) || realPath == dir {
					realAllowed = true
					break
				}
			}
		}

		if !realAllowed {
			return "", fmt.Errorf("access denied: symbolic link points to disallowed location '%s'", realPath)
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
		"../",      // Upward traversal
		"..\\",     // Windows upward traversal
		"/etc/",    // System configuration
		"/dev/",    // Device files
		"/proc/",   // Process information
		"/sys/",    // System information
		"c:\\",     // Windows system root directory
		"c:/",      // Windows system root directory
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
