package tools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/log"
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

const (
	ToolReadFile    = "read_file"
	ToolWriteFile   = "write_file"
	ToolListFiles   = "list_files"
	ToolDeleteFile  = "delete_file"
	ToolGetFileInfo = "get_file_info"
)

// MaxReadFileSize is the maximum file size allowed for ReadFile (10 MB).
// This prevents OOM when reading large files into memory.
const MaxReadFileSize = 10 * 1024 * 1024

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

// FileTools provides file operation handlers.
// Use NewFileTools to create an instance, then either:
// - Call methods directly (for MCP)
// - Use RegisterFileTools to register with Genkit
type FileTools struct {
	pathVal *security.Path
	logger  log.Logger
}

// NewFileTools creates a FileTools instance.
func NewFileTools(pathVal *security.Path, logger log.Logger) (*FileTools, error) {
	if pathVal == nil {
		return nil, fmt.Errorf("path validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &FileTools{pathVal: pathVal, logger: logger}, nil
}

// RegisterFileTools registers all file operation tools with Genkit.
func RegisterFileTools(g *genkit.Genkit, ft *FileTools) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if ft == nil {
		return nil, fmt.Errorf("FileTools is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, ToolReadFile,
			"Read the complete content of a text-based file. "+
				"Use this to examine source code, configuration files, logs, or documentation. "+
				"Supports files up to 10MB. Binary files are not supported and will return an error. "+
				"Returns: file path, content (UTF-8), size in bytes, and line count. "+
				"Common errors: file not found (verify path with list_files), "+
				"permission denied, file too large, binary file detected.",
			WithEvents(ToolReadFile, ft.ReadFile)),
		genkit.DefineTool(g, ToolWriteFile,
			"Write or create a text-based file with the specified content. "+
				"Creates parent directories automatically if they don't exist. "+
				"Overwrites existing files without confirmation. "+
				"Use this for: creating new files, updating configuration, saving generated content. "+
				"Returns: file path, bytes written, whether file was created or updated. "+
				"Common errors: permission denied, disk full, invalid path.",
			WithEvents(ToolWriteFile, ft.WriteFile)),
		genkit.DefineTool(g, ToolListFiles,
			"List files and subdirectories in a directory. "+
				"Returns file names, sizes, types (file/directory), and modification times. "+
				"Does not recurse into subdirectories (use recursively for deep exploration). "+
				"Use this to: explore project structure, find files by name, verify paths. "+
				"Tip: Start from the project root and navigate down to find specific files.",
			WithEvents(ToolListFiles, ft.ListFiles)),
		genkit.DefineTool(g, ToolDeleteFile,
			"Permanently delete a file or empty directory. "+
				"WARNING: This action cannot be undone. "+
				"Only deletes empty directories (use with caution). "+
				"Returns: confirmation of deletion with file path. "+
				"Common errors: file not found, directory not empty, permission denied.",
			WithEvents(ToolDeleteFile, ft.DeleteFile)),
		genkit.DefineTool(g, ToolGetFileInfo,
			"Get detailed metadata about a file without reading its contents. "+
				"Returns: file size, modification time, permissions, and type (file/directory). "+
				"Use this to: check if a file exists, verify file size before reading, "+
				"determine file type without opening it. "+
				"More efficient than read_file when you only need metadata.",
			WithEvents(ToolGetFileInfo, ft.GetFileInfo)),
	}, nil
}

// ReadFile reads and returns the complete content of a file with security validation.
func (f *FileTools) ReadFile(_ *ai.ToolContext, input ReadFileInput) (Result, error) {
	f.logger.Info("ReadFile called", "path", input.Path)

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
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
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to open file: %v", err),
			},
		}, nil
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to stat file: %v", err),
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
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read file: %v", err),
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
func (f *FileTools) WriteFile(_ *ai.ToolContext, input WriteFileInput) (Result, error) {
	f.logger.Info("WriteFile called", "path", input.Path)

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	dir := filepath.Dir(safePath)
	if mkdirErr := os.MkdirAll(dir, 0o750); mkdirErr != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to create directory: %v", mkdirErr),
			},
		}, nil
	}

	// #nosec G304 - safePath is validated
	file, err := os.OpenFile(safePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to open file: %v", err),
			},
		}, nil
	}
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString(input.Content); err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to write file: %v", err),
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
func (f *FileTools) ListFiles(_ *ai.ToolContext, input ListFilesInput) (Result, error) {
	f.logger.Info("ListFiles called", "path", input.Path)

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	entries, err := os.ReadDir(safePath)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read directory: %v", err),
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
func (f *FileTools) DeleteFile(_ *ai.ToolContext, input DeleteFileInput) (Result, error) {
	f.logger.Info("DeleteFile called", "path", input.Path)

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	if err := os.Remove(safePath); err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to delete file: %v", err),
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

// GetFileInfo gets file metadata.
func (f *FileTools) GetFileInfo(_ *ai.ToolContext, input GetFileInfoInput) (Result, error) {
	f.logger.Info("GetFileInfo called", "path", input.Path)

	safePath, err := f.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	info, err := os.Stat(safePath)
	if err != nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to get file info: %v", err),
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
