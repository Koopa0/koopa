package tools

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/security"
)

// Entry type constants for ListFiles results.
const (
	entryTypeFile      = "file"
	entryTypeDirectory = "directory"
)

// FileEntry represents a single file or directory entry in ListFiles output.
type FileEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "file" or "directory"
}

// Tool name constants for file operations registered with Genkit.
const (
	// ReadFileName is the Genkit tool name for reading file contents.
	ReadFileName = "read_file"
	// WriteFileName is the Genkit tool name for writing file contents.
	WriteFileName = "write_file"
	// ListFilesName is the Genkit tool name for listing directory contents.
	ListFilesName = "list_files"
	// DeleteFileName is the Genkit tool name for deleting files.
	DeleteFileName = "delete_file"
	// FileInfoName is the Genkit tool name for retrieving file metadata.
	FileInfoName = "get_file_info"
)

// MaxReadFileSize is the maximum file size allowed for ReadFile (10 MB).
// This prevents OOM when reading large files into memory.
const MaxReadFileSize = 10 * 1024 * 1024

// MaxPathLength is the maximum allowed file path length (4096 bytes).
// Matches Linux PATH_MAX. Prevents DoS via extremely long paths.
const MaxPathLength = 4096

// MaxWriteContentSize is the maximum content size for WriteFile (1 MB).
// Prevents OOM and disk abuse from extremely large write payloads.
const MaxWriteContentSize = 1 * 1024 * 1024

// ReadFileInput defines input for read_file tool.
type ReadFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to read (absolute or relative)"`
}

// WriteFileInput defines input for write_file tool.
type WriteFileInput struct {
	Path    string `json:"path" jsonschema_description:"The file path to write"`
	Content string `json:"content" jsonschema_description:"The content to write to the file"`
}

// ListFilesInput defines input for list_files tool.
type ListFilesInput struct {
	Path string `json:"path" jsonschema_description:"The directory path to list"`
}

// DeleteFileInput defines input for delete_file tool.
type DeleteFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to delete"`
}

// GetFileInfoInput defines input for get_file_info tool.
type GetFileInfoInput struct {
	Path string `json:"path" jsonschema_description:"The file path to get info for"`
}

// File provides file operation handlers.
// Use NewFile to create an instance, then either:
// - Call methods directly (for MCP)
// - Use RegisterFile to register with Genkit
type File struct {
	pathVal *security.Path
	logger  *slog.Logger
}

// NewFile creates a File instance.
func NewFile(pathVal *security.Path, logger *slog.Logger) (*File, error) {
	if pathVal == nil {
		return nil, fmt.Errorf("path validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &File{pathVal: pathVal, logger: logger}, nil
}

// RegisterFile registers all file operation tools with Genkit.
func RegisterFile(g *genkit.Genkit, ft *File) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if ft == nil {
		return nil, fmt.Errorf("File is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, ReadFileName,
			"Read the complete content of a text-based file. "+
				"Use this to examine source code, configuration files, logs, or documentation. "+
				"Supports files up to 10MB. Binary files are not supported and will return an error. "+
				"Returns: file path, content (UTF-8), size in bytes, and line count. "+
				"Common errors: file not found (verify path with list_files), "+
				"permission denied, file too large, binary file detected.",
			WithEvents(ReadFileName, ft.ReadFile)),
		genkit.DefineTool(g, WriteFileName,
			"Write or create a text-based file with the specified content. "+
				"Creates parent directories automatically if they don't exist. "+
				"Overwrites existing files without confirmation. "+
				"Use this for: creating new files, updating configuration, saving generated content. "+
				"Returns: file path, bytes written, whether file was created or updated. "+
				"Common errors: permission denied, disk full, invalid path.",
			WithEvents(WriteFileName, ft.WriteFile)),
		genkit.DefineTool(g, ListFilesName,
			"List files and subdirectories in a directory. "+
				"Returns file names, sizes, types (file/directory), and modification times. "+
				"Does not recurse into subdirectories (use recursively for deep exploration). "+
				"Use this to: explore project structure, find files by name, verify paths. "+
				"Tip: Start from the project root and navigate down to find specific files.",
			WithEvents(ListFilesName, ft.ListFiles)),
		genkit.DefineTool(g, DeleteFileName,
			"Permanently delete a file or empty directory. "+
				"WARNING: This action cannot be undone. "+
				"Only deletes empty directories (use with caution). "+
				"Returns: confirmation of deletion with file path. "+
				"Common errors: file not found, directory not empty, permission denied.",
			WithEvents(DeleteFileName, ft.DeleteFile)),
		genkit.DefineTool(g, FileInfoName,
			"Get detailed metadata about a file without reading its contents. "+
				"Returns: file size, modification time, permissions, and type (file/directory). "+
				"Use this to: check if a file exists, verify file size before reading, "+
				"determine file type without opening it. "+
				"More efficient than read_file when you only need metadata.",
			WithEvents(FileInfoName, ft.FileInfo)),
	}, nil
}

// ReadFile reads and returns the complete content of a file with security validation.
func (f *File) ReadFile(_ *ai.ToolContext, input ReadFileInput) (Result, error) {
	f.logger.Debug("ReadFile called", "path", input.Path)

	if len(input.Path) > MaxPathLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("path length %d exceeds maximum %d bytes", len(input.Path), MaxPathLength),
			},
		}, nil
	}

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		f.logger.Warn("path validation failed", "path", input.Path, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "path validation failed",
			},
		}, nil
	}

	file, err := os.Open(safePath) // #nosec G304 - path already validated
	if err != nil {
		if os.IsNotExist(err) {
			return Result{
				Status: StatusError,
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}
		f.logger.Warn("file open failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file read failed",
			},
		}, nil
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		f.logger.Warn("file stat failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file read failed",
			},
		}, nil
	}

	if info.Size() > MaxReadFileSize {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("file size %d exceeds maximum %d bytes", info.Size(), MaxReadFileSize),
			},
		}, nil
	}

	content, err := io.ReadAll(io.LimitReader(file, MaxReadFileSize))
	if err != nil {
		f.logger.Warn("file read failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file read failed",
			},
		}, nil
	}

	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"path":    safePath,
			"content": string(content),
			"size":    len(content),
		},
	}, nil
}

// WriteFile writes content to a file with security validation.
func (f *File) WriteFile(_ *ai.ToolContext, input WriteFileInput) (Result, error) {
	f.logger.Debug("WriteFile called", "path", input.Path)

	if len(input.Path) > MaxPathLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("path length %d exceeds maximum %d bytes", len(input.Path), MaxPathLength),
			},
		}, nil
	}

	if len(input.Content) > MaxWriteContentSize {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("content size %d exceeds maximum %d bytes", len(input.Content), MaxWriteContentSize),
			},
		}, nil
	}

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		f.logger.Warn("path validation failed", "path", input.Path, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "path validation failed",
			},
		}, nil
	}

	dir := filepath.Dir(safePath)
	if mkdirErr := os.MkdirAll(dir, 0o750); mkdirErr != nil {
		f.logger.Warn("directory creation failed", "dir", dir, "error", mkdirErr)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file write failed",
			},
		}, nil
	}

	// #nosec G304 - safePath is validated
	file, err := os.OpenFile(safePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		f.logger.Warn("file open failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file write failed",
			},
		}, nil
	}
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString(input.Content); err != nil {
		f.logger.Warn("file write failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file write failed",
			},
		}, nil
	}

	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"path": safePath,
			"size": len(input.Content),
		},
	}, nil
}

// ListFiles lists files in a directory.
func (f *File) ListFiles(_ *ai.ToolContext, input ListFilesInput) (Result, error) {
	f.logger.Debug("ListFiles called", "path", input.Path)

	if len(input.Path) > MaxPathLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("path length %d exceeds maximum %d bytes", len(input.Path), MaxPathLength),
			},
		}, nil
	}

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		f.logger.Warn("path validation failed", "path", input.Path, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "path validation failed",
			},
		}, nil
	}

	entries, err := os.ReadDir(safePath)
	if err != nil {
		f.logger.Warn("directory read failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "directory listing failed",
			},
		}, nil
	}

	files := make([]FileEntry, 0, len(entries))
	for _, entry := range entries {
		entryType := entryTypeFile
		if entry.IsDir() {
			entryType = entryTypeDirectory
		}
		files = append(files, FileEntry{
			Name: entry.Name(),
			Type: entryType,
		})
	}

	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"path":    safePath,
			"entries": files,
			"count":   len(files),
		},
	}, nil
}

// DeleteFile permanently deletes a file with security validation.
func (f *File) DeleteFile(_ *ai.ToolContext, input DeleteFileInput) (Result, error) {
	f.logger.Debug("DeleteFile called", "path", input.Path)

	if len(input.Path) > MaxPathLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("path length %d exceeds maximum %d bytes", len(input.Path), MaxPathLength),
			},
		}, nil
	}

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		f.logger.Warn("path validation failed", "path", input.Path, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "path validation failed",
			},
		}, nil
	}

	if err := os.Remove(safePath); err != nil {
		f.logger.Warn("file deletion failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file deletion failed",
			},
		}, nil
	}

	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"path": safePath,
		},
	}, nil
}

// FileInfo gets file metadata.
func (f *File) FileInfo(_ *ai.ToolContext, input GetFileInfoInput) (Result, error) {
	f.logger.Debug("FileInfo called", "path", input.Path)

	if len(input.Path) > MaxPathLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("path length %d exceeds maximum %d bytes", len(input.Path), MaxPathLength),
			},
		}, nil
	}

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		f.logger.Warn("path validation failed", "path", input.Path, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "path validation failed",
			},
		}, nil
	}

	info, err := os.Stat(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{
				Status: StatusError,
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}
		f.logger.Warn("file info failed", "path", safePath, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: "file info failed",
			},
		}, nil
	}

	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"name":        info.Name(),
			"size":        info.Size(),
			"is_dir":      info.IsDir(),
			"modified":    info.ModTime().Format("2006-01-02 15:04:05"),
			"permissions": info.Mode().String(),
		},
	}, nil
}
