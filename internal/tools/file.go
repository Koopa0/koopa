package tools

// file.go defines file operation tools with security validation.
//
// Provides 5 file tools: readFile, writeFile, listFiles, deleteFile, getFileInfo.
// All operations use security.PathValidator to prevent path traversal attacks (CWE-22).
// File permissions: 0600 for created files, 0750 for directories.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/ai"
)

// ============================================================================
// Kit Methods (Phase 1 - Structured Return Values)
// ============================================================================

// ReadFile reads and returns the content of a file.
//
// Error handling:
//   - Agent Error (file not found, permission denied): Return Result{Error: ...}, nil
//   - System Error (disk failure): Return Result{}, error (rare in practice)
func (k *Kit) ReadFile(ctx *ai.ToolContext, input ReadFileInput) (Result, error) {
	k.log("info", "ReadFile called", "path", input.Path)

	// Validate path (security check)
	safePath, err := k.pathVal.Validate(input.Path)
	if err != nil {
		// Agent Error: Security validation failed
		k.log("error", "ReadFile path validation failed", "path", input.Path, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	// Read file
	content, err := os.ReadFile(safePath) // #nosec G304 -- validated above
	if err != nil {
		// Determine error type
		if os.IsNotExist(err) {
			// Agent Error: File not found
			k.log("error", "ReadFile file not found", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: fmt.Sprintf("File not found: %s", input.Path),
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}

		if os.IsPermission(err) {
			// Agent Error: Permission denied
			k.log("error", "ReadFile permission denied", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Permission denied",
				Error: &Error{
					Code:    ErrCodePermission,
					Message: fmt.Sprintf("permission denied: %s", input.Path),
				},
			}, nil
		}

		// Other I/O errors (treat as Agent Error for safety)
		k.log("error", "ReadFile I/O error", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Failed to read file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read file: %v", err),
			},
		}, nil
	}

	// Success
	k.log("info", "ReadFile succeeded", "path", safePath, "size", len(content))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully read file: %s", safePath),
		Data: map[string]any{
			"path":    safePath,
			"content": string(content),
			"size":    len(content),
		},
	}, nil
}

// WriteFile writes content to a file with secure permissions.
//
// Error handling:
//   - Agent Error (path validation, permission denied, symlink): Return Result{Error: ...}, nil
//   - System Error (disk failure): Return Result{}, error (rare)
func (k *Kit) WriteFile(ctx *ai.ToolContext, input WriteFileInput) (Result, error) {
	k.log("info", "WriteFile called", "path", input.Path)

	// Validate path (security check)
	safePath, err := k.pathVal.Validate(input.Path)
	if err != nil {
		k.log("error", "WriteFile path validation failed", "path", input.Path, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	// Ensure directory exists (use 0750 permission)
	dir := filepath.Dir(safePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		k.log("error", "WriteFile unable to create directory", "dir", dir, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to create directory",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to create directory: %v", err),
			},
		}, nil
	}

	// Security: safePath is validated by security.Path.Validate() which:
	// - Prevents directory traversal (CWE-22)
	// - Resolves and validates symlinks
	// - Enforces allowed directory restrictions
	// gosec G304 is suppressed as path validation is performed above
	file, err := os.OpenFile(safePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304
	if err != nil {
		// Check if it's a symlink-related error
		if info, statErr := os.Lstat(safePath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			k.log("error", "WriteFile refusing to write to symlink", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Refusing to write to symlink",
				Error: &Error{
					Code:    ErrCodeSecurity,
					Message: fmt.Sprintf("refusing to write to symlink: %s", safePath),
				},
			}, nil
		}

		if os.IsPermission(err) {
			k.log("error", "WriteFile permission denied", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Permission denied",
				Error: &Error{
					Code:    ErrCodePermission,
					Message: fmt.Sprintf("permission denied: %s", input.Path),
				},
			}, nil
		}

		k.log("error", "WriteFile unable to open file", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to open file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to open file: %v", err),
			},
		}, nil
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			k.log("error", "WriteFile failed to close file", "path", safePath, "error", closeErr)
		}
	}()

	// Write content
	if _, err := file.Write([]byte(input.Content)); err != nil {
		k.log("error", "WriteFile unable to write", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to write file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to write file: %v", err),
			},
		}, nil
	}

	// Success
	k.log("info", "WriteFile succeeded", "path", safePath, "size", len(input.Content))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully wrote file: %s", safePath),
		Data: map[string]any{
			"path": safePath,
			"size": len(input.Content),
		},
	}, nil
}

// ListFiles lists all files and subdirectories in a directory.
//
// Error handling:
//   - Agent Error (directory not found, permission denied): Return Result{Error: ...}, nil
//   - System Error (disk failure): Return Result{}, error (rare)
func (k *Kit) ListFiles(ctx *ai.ToolContext, input ListFilesInput) (Result, error) {
	k.log("info", "ListFiles called", "path", input.Path)

	// Validate path (security check)
	safePath, err := k.pathVal.Validate(input.Path)
	if err != nil {
		k.log("error", "ListFiles path validation failed", "path", input.Path, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	// Read directory
	entries, err := os.ReadDir(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			k.log("error", "ListFiles directory not found", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: fmt.Sprintf("Directory not found: %s", input.Path),
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("directory not found: %s", input.Path),
				},
			}, nil
		}

		if os.IsPermission(err) {
			k.log("error", "ListFiles permission denied", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Permission denied",
				Error: &Error{
					Code:    ErrCodePermission,
					Message: fmt.Sprintf("permission denied: %s", input.Path),
				},
			}, nil
		}

		k.log("error", "ListFiles unable to read directory", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to read directory",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read directory: %v", err),
			},
		}, nil
	}

	// Build file list
	var files []map[string]any
	for _, entry := range entries {
		fileType := "file"
		if entry.IsDir() {
			fileType = "directory"
		}
		files = append(files, map[string]any{
			"name": entry.Name(),
			"type": fileType,
		})
	}

	// Success
	k.log("info", "ListFiles succeeded", "path", safePath, "count", len(files))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully listed %d entries in: %s", len(files), safePath),
		Data: map[string]any{
			"path":    safePath,
			"entries": files,
			"count":   len(files),
		},
	}, nil
}

// DeleteFile permanently deletes a file from the filesystem.
// WARNING: This action is irreversible!
//
// Error handling:
//   - Agent Error (file not found, permission denied, symlink): Return Result{Error: ...}, nil
//   - System Error (disk failure): Return Result{}, error (rare)
func (k *Kit) DeleteFile(ctx *ai.ToolContext, input DeleteFileInput) (Result, error) {
	k.log("info", "DeleteFile called", "path", input.Path)

	// Validate path (security check)
	safePath, err := k.pathVal.Validate(input.Path)
	if err != nil {
		k.log("error", "DeleteFile path validation failed", "path", input.Path, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	// Security: Check for symbolic links before deletion (prevent deleting unintended targets)
	info, err := os.Lstat(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			k.log("error", "DeleteFile file not found", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: fmt.Sprintf("File not found: %s", input.Path),
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}

		k.log("error", "DeleteFile unable to stat file", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to stat file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to stat file: %v", err),
			},
		}, nil
	}

	if info.Mode()&os.ModeSymlink != 0 {
		k.log("error", "DeleteFile refusing to delete symlink", "path", safePath)
		return Result{
			Status:  StatusError,
			Message: "Refusing to delete symlink",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("refusing to delete symlink: %s", safePath),
			},
		}, nil
	}

	// Delete file
	if err := os.Remove(safePath); err != nil {
		if os.IsPermission(err) {
			k.log("error", "DeleteFile permission denied", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Permission denied",
				Error: &Error{
					Code:    ErrCodePermission,
					Message: fmt.Sprintf("permission denied: %s", input.Path),
				},
			}, nil
		}

		k.log("error", "DeleteFile unable to delete", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to delete file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to delete file: %v", err),
			},
		}, nil
	}

	// Success
	k.log("info", "DeleteFile succeeded", "path", safePath)
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully deleted file: %s", safePath),
		Data: map[string]any{
			"path": safePath,
		},
	}, nil
}

// GetFileInfo returns detailed metadata about a file or directory.
//
// Error handling:
//   - Agent Error (file not found, permission denied): Return Result{Error: ...}, nil
//   - System Error (disk failure): Return Result{}, error (rare)
func (k *Kit) GetFileInfo(ctx *ai.ToolContext, input GetFileInfoInput) (Result, error) {
	k.log("info", "GetFileInfo called", "path", input.Path)

	// Validate path (security check)
	safePath, err := k.pathVal.Validate(input.Path)
	if err != nil {
		k.log("error", "GetFileInfo path validation failed", "path", input.Path, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	// Get file info
	info, err := os.Stat(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			k.log("error", "GetFileInfo file not found", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: fmt.Sprintf("File not found: %s", input.Path),
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}

		if os.IsPermission(err) {
			k.log("error", "GetFileInfo permission denied", "path", safePath)
			return Result{
				Status:  StatusError,
				Message: "Permission denied",
				Error: &Error{
					Code:    ErrCodePermission,
					Message: fmt.Sprintf("permission denied: %s", input.Path),
				},
			}, nil
		}

		k.log("error", "GetFileInfo unable to get info", "path", safePath, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Unable to get file information",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to get file information: %v", err),
			},
		}, nil
	}

	// Success
	k.log("info", "GetFileInfo succeeded", "path", safePath)
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully retrieved file info: %s", safePath),
		Data: map[string]any{
			"name":        info.Name(),
			"size":        info.Size(),
			"is_dir":      info.IsDir(),
			"modified":    info.ModTime().Format("2006-01-02 15:04:05"),
			"permissions": info.Mode().String(),
		},
	}, nil
}
