package tools

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/security"
)

// FileToolset name constant.
const FileToolsetName = "file"

// ReadFileInput defines input for readFile tool.
type ReadFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to read (absolute or relative)"`
}

// WriteFileInput defines input for writeFile tool.
type WriteFileInput struct {
	Path    string `json:"path" jsonschema_description:"The file path to write"`
	Content string `json:"content" jsonschema_description:"The content to write to the file"`
}

// ListFilesInput defines input for listFiles tool.
type ListFilesInput struct {
	Path string `json:"path" jsonschema_description:"The directory path to list"`
}

// DeleteFileInput defines input for deleteFile tool.
type DeleteFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to delete"`
}

// GetFileInfoInput defines input for getFileInfo tool.
type GetFileInfoInput struct {
	Path string `json:"path" jsonschema_description:"The file path to get info for"`
}

// FileToolset provides file operation tools such as reading, writing, and managing files.
// It implements the Toolset interface.
type FileToolset struct {
	pathVal *security.Path
	logger  log.Logger
}

// NewFileToolset creates a new FileToolset.
func NewFileToolset(pathVal *security.Path, logger log.Logger) (*FileToolset, error) {
	if pathVal == nil {
		return nil, fmt.Errorf("path validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &FileToolset{
		pathVal: pathVal,
		logger:  logger,
	}, nil
}

// Name returns the toolset identifier.
func (fs *FileToolset) Name() string {
	return FileToolsetName
}

// Tools returns all file operation tools provided by this toolset.
func (fs *FileToolset) Tools(ctx agent.ReadonlyContext) ([]Tool, error) {
	return []Tool{
		NewTool(
			"readFile",
			"Read the complete content of any text-based file.",
			false, // not long running
			fs.ReadFile,
		),
		NewTool(
			"writeFile",
			"Write or create any text-based file.",
			false,
			fs.WriteFile,
		),
		NewTool(
			"listFiles",
			"List all files and subdirectories in a directory.",
			false,
			fs.ListFiles,
		),
		NewTool(
			"deleteFile",
			"Delete a file permanently.",
			false,
			fs.DeleteFile,
		),
		NewTool(
			"getFileInfo",
			"Get detailed metadata about a file.",
			false,
			fs.GetFileInfo,
		),
	}, nil
}

// ReadFile reads and returns the complete content of a file with security validation.
func (fs *FileToolset) ReadFile(ctx *ai.ToolContext, input ReadFileInput) (Result, error) {
	fs.logger.Info("ReadFile called", "path", input.Path)

	// Validate path (security check)
	safePath, err := fs.pathVal.Validate(input.Path)
	if err != nil {
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
	content, err := os.ReadFile(safePath) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return Result{
				Status:  StatusError,
				Message: fmt.Sprintf("File not found: %s", input.Path),
				Error: &Error{
					Code:    ErrCodeNotFound,
					Message: fmt.Sprintf("file not found: %s", input.Path),
				},
			}, nil
		}
		return Result{
			Status:  StatusError,
			Message: "Failed to read file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read file: %v", err),
			},
		}, nil
	}

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

// WriteFile writes content to a file with security validation and automatic directory creation.
func (fs *FileToolset) WriteFile(ctx *ai.ToolContext, input WriteFileInput) (Result, error) {
	fs.logger.Info("WriteFile called", "path", input.Path)

	safePath, err := fs.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	dir := filepath.Dir(safePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to create directory",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to create directory: %v", err),
			},
		}, nil
	}

	// #nosec G304 - safePath is validated by pathVal.Validate() above
	file, err := os.OpenFile(safePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to open file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to open file: %v", err),
			},
		}, nil
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write([]byte(input.Content)); err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to write file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to write file: %v", err),
			},
		}, nil
	}

	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully wrote file: %s", safePath),
		Data: map[string]any{
			"path": safePath,
			"size": len(input.Content),
		},
	}, nil
}

// ListFiles lists files in a directory.
func (fs *FileToolset) ListFiles(ctx *ai.ToolContext, input ListFilesInput) (Result, error) {
	fs.logger.Info("ListFiles called", "path", input.Path)

	safePath, err := fs.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	entries, err := os.ReadDir(safePath)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to read directory",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to read directory: %v", err),
			},
		}, nil
	}

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

// DeleteFile permanently deletes a file with security validation.
func (fs *FileToolset) DeleteFile(ctx *ai.ToolContext, input DeleteFileInput) (Result, error) {
	fs.logger.Info("DeleteFile called", "path", input.Path)

	safePath, err := fs.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	if err := os.Remove(safePath); err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to delete file",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to delete file: %v", err),
			},
		}, nil
	}

	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully deleted file: %s", safePath),
		Data: map[string]any{
			"path": safePath,
		},
	}, nil
}

// GetFileInfo gets file metadata.
func (fs *FileToolset) GetFileInfo(ctx *ai.ToolContext, input GetFileInfoInput) (Result, error) {
	fs.logger.Info("GetFileInfo called", "path", input.Path)

	safePath, err := fs.pathVal.Validate(input.Path)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Path validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("path validation failed: %v", err),
			},
		}, nil
	}

	info, err := os.Stat(safePath)
	if err != nil {
		return Result{
			Status:  StatusError,
			Message: "Unable to get file information",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("unable to get file information: %v", err),
			},
		}, nil
	}

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
