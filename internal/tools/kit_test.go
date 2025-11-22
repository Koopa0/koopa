package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
)

// mockKnowledgeSearcherKit is a mock implementation for Kit tests (uses correct interface)
type mockKnowledgeSearcherKit struct{}

func (m *mockKnowledgeSearcherKit) Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error) {
	return []knowledge.Result{}, nil
}

type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(msg string, args ...any) {
	m.logs = append(m.logs, fmt.Sprintf("INFO: %s %v", msg, args))
}

func (m *mockLogger) Error(msg string, args ...any) {
	m.logs = append(m.logs, fmt.Sprintf("ERROR: %s %v", msg, args))
}

// Helper to create Kit for testing
func newTestKit(t *testing.T) *Kit {
	t.Helper()

	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	return kit
}

// TestNewKit_Validation tests NewKit validation
func TestNewKit_Validation(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	tests := []struct {
		name    string
		cfg     KitConfig
		wantErr string
	}{
		{
			name: "all fields valid",
			cfg: KitConfig{
				PathVal:        pathVal,
				CmdVal:         security.NewCommand(),
				EnvVal:         security.NewEnv(),
				HTTPVal:        &mockHTTPValidator{},
				KnowledgeStore: &mockKnowledgeSearcherKit{},
			},
			wantErr: "",
		},
		{
			name: "missing PathVal",
			cfg: KitConfig{
				CmdVal:         security.NewCommand(),
				EnvVal:         security.NewEnv(),
				HTTPVal:        &mockHTTPValidator{},
				KnowledgeStore: &mockKnowledgeSearcherKit{},
			},
			wantErr: "PathVal is required",
		},
		{
			name: "missing CmdVal",
			cfg: KitConfig{
				PathVal:        pathVal,
				EnvVal:         security.NewEnv(),
				HTTPVal:        &mockHTTPValidator{},
				KnowledgeStore: &mockKnowledgeSearcherKit{},
			},
			wantErr: "CmdVal is required",
		},
		{
			name: "missing EnvVal",
			cfg: KitConfig{
				PathVal:        pathVal,
				CmdVal:         security.NewCommand(),
				HTTPVal:        &mockHTTPValidator{},
				KnowledgeStore: &mockKnowledgeSearcherKit{},
			},
			wantErr: "EnvVal is required",
		},
		{
			name: "missing HTTPVal",
			cfg: KitConfig{
				PathVal:        pathVal,
				CmdVal:         security.NewCommand(),
				EnvVal:         security.NewEnv(),
				KnowledgeStore: &mockKnowledgeSearcherKit{},
			},
			wantErr: "HTTPVal is required",
		},
		{
			name: "missing KnowledgeStore",
			cfg: KitConfig{
				PathVal: pathVal,
				CmdVal:  security.NewCommand(),
				EnvVal:  security.NewEnv(),
				HTTPVal: &mockHTTPValidator{},
			},
			wantErr: "KnowledgeStore is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kit, err := NewKit(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("NewKit() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("NewKit() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("NewKit() unexpected error = %v", err)
				return
			}
			if kit == nil {
				t.Error("NewKit() returned nil kit")
			}
		})
	}
}

// TestKit_ReadFile tests ReadFile method
func TestKit_ReadFile(t *testing.T) {
	// Create temp dir and kit with same tmpDir for path validation
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	// Create temp file for testing (in the same tmpDir that Kit's pathVal allows)
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(testContent), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name       string
		input      ReadFileInput
		wantStatus Status
		wantCode   ErrorCode
		checkData  bool
	}{
		{
			name:       "success",
			input:      ReadFileInput{Path: testFile},
			wantStatus: StatusSuccess,
			checkData:  true,
		},
		{
			name:       "file not found",
			input:      ReadFileInput{Path: filepath.Join(tmpDir, "nonexistent.txt")},
			wantStatus: StatusError,
			wantCode:   ErrCodeNotFound,
		},
		{
			name:       "path traversal attack",
			input:      ReadFileInput{Path: "../../etc/passwd"},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{
				Context: context.Background(),
			}

			result, err := kit.ReadFile(ctx, tt.input)

			// Should always return nil error (Agent Error pattern)
			if err != nil {
				t.Errorf("ReadFile() returned unexpected error: %v", err)
				return
			}

			// Check status
			if result.Status != tt.wantStatus {
				t.Errorf("ReadFile() status = %v, want %v", result.Status, tt.wantStatus)
			}

			// Check error code if error expected
			if tt.wantStatus == StatusError {
				if result.Error == nil {
					t.Error("ReadFile() Error is nil, want error")
					return
				}
				if result.Error.Code != tt.wantCode {
					t.Errorf("ReadFile() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			// Check data if success expected
			if tt.checkData {
				if result.Data == nil {
					t.Error("ReadFile() Data is nil, want data")
					return
				}
				data, ok := result.Data.(map[string]any)
				if !ok {
					t.Error("ReadFile() Data is not map[string]any")
					return
				}
				content, ok := data["content"].(string)
				if !ok || content != testContent {
					t.Errorf("ReadFile() content = %v, want %v", content, testContent)
				}
			}
		})
	}
}

// TestResult_JSONSerialization tests Result can be serialized to JSON
func TestResult_JSONSerialization(t *testing.T) {
	result := Result{
		Status:  StatusSuccess,
		Message: "Test message",
		Data: map[string]any{
			"key": "value",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal Result: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal Result: %v", err)
	}

	// Check fields
	if decoded["status"] != string(StatusSuccess) {
		t.Errorf("status = %v, want %v", decoded["status"], StatusSuccess)
	}
	if decoded["message"] != "Test message" {
		t.Errorf("message = %v, want Test message", decoded["message"])
	}
}

// TestKit_Register tests Kit.Register method
func TestKit_Register(t *testing.T) {
	kit := newTestKit(t)

	ctx := context.Background()
	g := genkit.Init(ctx)

	err := kit.Register(g)
	if err != nil {
		t.Errorf("Register() error = %v, want nil", err)
	}

	// Verify tools are registered by checking a few
	if tool := genkit.LookupTool(g, "readFile"); tool == nil {
		t.Error("readFile tool not registered")
	}
	if tool := genkit.LookupTool(g, "currentTime"); tool == nil {
		t.Error("currentTime tool not registered")
	}
	if tool := genkit.LookupTool(g, "httpGet"); tool == nil {
		t.Error("httpGet tool not registered")
	}
	if tool := genkit.LookupTool(g, "searchHistory"); tool == nil {
		t.Error("searchHistory tool not registered")
	}
}

// TestKit_Register_NilGenkit tests Register with nil genkit
func TestKit_Register_NilGenkit(t *testing.T) {
	kit := newTestKit(t)

	err := kit.Register(nil)
	if err == nil {
		t.Error("Register(nil) error = nil, want error")
	}
}

// TestToolRegistration tests that all expected tools are registered
// Note: Following V3.0 design, we no longer maintain a global toolNames list.
// Instead, this test verifies tools through Genkit's LookupTool API.
func TestToolRegistration(t *testing.T) {
	kit := newTestKit(t)
	g := genkit.Init(context.Background())

	// Register all tools
	if err := kit.Register(g); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify all expected tools are registered
	expectedTools := []string{
		"readFile", "writeFile", "listFiles", "deleteFile", "getFileInfo",
		"currentTime", "executeCommand", "getEnv",
		"httpGet",
		"searchHistory", "searchDocuments", "searchSystemKnowledge",
	}

	for _, toolName := range expectedTools {
		tool := genkit.LookupTool(g, toolName)
		if tool == nil {
			t.Errorf("Expected tool %s not registered", toolName)
		}
	}

	// Verify total count
	if len(expectedTools) != 12 {
		t.Errorf("Expected 12 tools, but test only checks %d", len(expectedTools))
	}
}

// TestKit_All tests Kit.All method
func TestKit_All(t *testing.T) {
	kit := newTestKit(t)

	ctx := context.Background()
	g := genkit.Init(ctx)

	// Register tools first
	if err := kit.Register(g); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Get all tools
	tools := kit.All(ctx, g)

	// Should return 12 tools
	if len(tools) != 12 {
		t.Errorf("All() returned %d tools, want 12", len(tools))
	}
}

// TestWithLogger tests the WithLogger option
func TestWithLogger(t *testing.T) {
	logger := &mockLogger{}

	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("NewKit() error = %v", err)
	}

	if kit.logger == nil {
		t.Error("kit.logger is nil, want logger")
	}

	// Test that logging works
	kit.log("info", "test message", "key", "value")
	if len(logger.logs) == 0 {
		t.Error("logger.logs is empty, want at least one log entry")
	}

	// Test error logging
	kit.log("error", "error message", "error", "test")
	if len(logger.logs) < 2 {
		t.Error("logger.logs should have at least 2 entries")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// ============================================================================
// File Tool Tests
// ============================================================================

// TestKit_WriteFile tests WriteFile method
func TestKit_WriteFile(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	tests := []struct {
		name       string
		input      WriteFileInput
		wantStatus Status
		wantCode   ErrorCode
	}{
		{
			name: "success",
			input: WriteFileInput{
				Path:    filepath.Join(tmpDir, "test_write.txt"),
				Content: "test content",
			},
			wantStatus: StatusSuccess,
		},
		{
			name: "create nested directories",
			input: WriteFileInput{
				Path:    filepath.Join(tmpDir, "nested", "dir", "file.txt"),
				Content: "nested content",
			},
			wantStatus: StatusSuccess,
		},
		{
			name: "path traversal attack",
			input: WriteFileInput{
				Path:    "../../etc/passwd",
				Content: "malicious",
			},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.WriteFile(ctx, tt.input)

			if err != nil {
				t.Errorf("WriteFile() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("WriteFile() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("WriteFile() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			// Verify file was created for success cases
			if tt.wantStatus == StatusSuccess {
				if _, err := os.Stat(tt.input.Path); os.IsNotExist(err) {
					t.Errorf("WriteFile() did not create file at %s", tt.input.Path)
				} else {
					// Read back and verify content
					content, err := os.ReadFile(tt.input.Path)
					if err == nil && string(content) != tt.input.Content {
						t.Errorf("WriteFile() content = %s, want %s", string(content), tt.input.Content)
					}
				}
			}
		})
	}
}

// TestKit_WriteFile_IOError tests WriteFile with IO errors
func TestKit_WriteFile_IOError(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	// Create a read-only directory to trigger permission error
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0555); err != nil {
		t.Fatalf("failed to create readonly dir: %v", err)
	}
	defer func() {
		_ = os.Chmod(readOnlyDir, 0755) // Restore permissions for cleanup
	}()

	ctx := &ai.ToolContext{Context: context.Background()}
	result, err := kit.WriteFile(ctx, WriteFileInput{
		Path:    filepath.Join(readOnlyDir, "file.txt"),
		Content: "test",
	})

	if err != nil {
		t.Errorf("WriteFile() returned unexpected error: %v", err)
		return
	}

	// Should get IO error
	if result.Status != StatusError {
		t.Errorf("WriteFile() status = %v, want StatusError", result.Status)
	}
}

// TestKit_ListFiles tests ListFiles method
func TestKit_ListFiles(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	// Create test files and directories
	testFile1 := filepath.Join(tmpDir, "file1.txt")
	testFile2 := filepath.Join(tmpDir, "file2.txt")
	testDir := filepath.Join(tmpDir, "subdir")

	if err := os.WriteFile(testFile1, []byte("test1"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.WriteFile(testFile2, []byte("test2"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.Mkdir(testDir, 0750); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	tests := []struct {
		name       string
		input      ListFilesInput
		wantStatus Status
		wantCode   ErrorCode
		checkFiles bool
	}{
		{
			name:       "success",
			input:      ListFilesInput{Path: tmpDir},
			wantStatus: StatusSuccess,
			checkFiles: true,
		},
		{
			name:       "directory not found",
			input:      ListFilesInput{Path: filepath.Join(tmpDir, "nonexistent")},
			wantStatus: StatusError,
			wantCode:   ErrCodeNotFound,
		},
		{
			name:       "path traversal attack",
			input:      ListFilesInput{Path: "../../etc"},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.ListFiles(ctx, tt.input)

			if err != nil {
				t.Errorf("ListFiles() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("ListFiles() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("ListFiles() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			if tt.checkFiles && result.Data != nil {
				data, ok := result.Data.(map[string]any)
				if !ok {
					t.Error("ListFiles() Data is not map[string]any")
					return
				}
				entries, ok := data["entries"]
				if !ok {
					t.Error("ListFiles() Data missing 'entries' field")
					return
				}
				entriesSlice, ok := entries.([]map[string]any)
				if !ok {
					t.Errorf("ListFiles() entries is not []map[string]any, got %T", entries)
					return
				}
				if len(entriesSlice) < 3 {
					t.Errorf("ListFiles() found %d entries, want at least 3", len(entriesSlice))
				}
			}
		})
	}
}

// TestKit_DeleteFile tests DeleteFile method
func TestKit_DeleteFile(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	tests := []struct {
		name       string
		setupFile  bool
		input      DeleteFileInput
		wantStatus Status
		wantCode   ErrorCode
	}{
		{
			name:       "success",
			setupFile:  true,
			input:      DeleteFileInput{Path: filepath.Join(tmpDir, "delete_me.txt")},
			wantStatus: StatusSuccess,
		},
		{
			name:       "file not found",
			setupFile:  false,
			input:      DeleteFileInput{Path: filepath.Join(tmpDir, "nonexistent.txt")},
			wantStatus: StatusError,
			wantCode:   ErrCodeNotFound,
		},
		{
			name:       "path traversal attack",
			setupFile:  false,
			input:      DeleteFileInput{Path: "../../etc/passwd"},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFile {
				if err := os.WriteFile(tt.input.Path, []byte("delete me"), 0600); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			}

			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.DeleteFile(ctx, tt.input)

			if err != nil {
				t.Errorf("DeleteFile() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("DeleteFile() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("DeleteFile() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			// Verify file was deleted for success cases
			if tt.wantStatus == StatusSuccess {
				if _, err := os.Stat(tt.input.Path); !os.IsNotExist(err) {
					t.Errorf("DeleteFile() did not delete file at %s", tt.input.Path)
				}
			}
		})
	}
}

// TestKit_GetFileInfo tests GetFileInfo method
func TestKit_GetFileInfo(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	testFile := filepath.Join(tmpDir, "info.txt")
	testContent := "test content"
	if err := os.WriteFile(testFile, []byte(testContent), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name       string
		input      GetFileInfoInput
		wantStatus Status
		wantCode   ErrorCode
		checkData  bool
	}{
		{
			name:       "success - file",
			input:      GetFileInfoInput{Path: testFile},
			wantStatus: StatusSuccess,
			checkData:  true,
		},
		{
			name:       "success - directory",
			input:      GetFileInfoInput{Path: tmpDir},
			wantStatus: StatusSuccess,
			checkData:  true,
		},
		{
			name:       "file not found",
			input:      GetFileInfoInput{Path: filepath.Join(tmpDir, "nonexistent.txt")},
			wantStatus: StatusError,
			wantCode:   ErrCodeNotFound,
		},
		{
			name:       "path traversal attack",
			input:      GetFileInfoInput{Path: "../../etc/passwd"},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.GetFileInfo(ctx, tt.input)

			if err != nil {
				t.Errorf("GetFileInfo() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("GetFileInfo() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("GetFileInfo() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			if tt.checkData && result.Data != nil {
				data, ok := result.Data.(map[string]any)
				if !ok {
					t.Error("GetFileInfo() Data is not map[string]any")
					return
				}
				if _, ok := data["name"]; !ok {
					t.Error("GetFileInfo() Data missing 'name' field")
				}
				if _, ok := data["size"]; !ok {
					t.Error("GetFileInfo() Data missing 'size' field")
				}
				if _, ok := data["is_dir"]; !ok {
					t.Error("GetFileInfo() Data missing 'is_dir' field")
				}
			}
		})
	}
}

// ============================================================================
// System Tool Tests
// ============================================================================

// TestKit_CurrentTime tests CurrentTime method
func TestKit_CurrentTime(t *testing.T) {
	kit := newTestKit(t)

	ctx := &ai.ToolContext{Context: context.Background()}
	result, err := kit.CurrentTime(ctx, CurrentTimeInput{})

	if err != nil {
		t.Errorf("CurrentTime() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("CurrentTime() status = %v, want %v", result.Status, StatusSuccess)
	}

	if result.Data == nil {
		t.Error("CurrentTime() Data is nil, want data")
		return
	}

	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Error("CurrentTime() Data is not map[string]any")
		return
	}

	if _, ok := data["timestamp"]; !ok {
		t.Error("CurrentTime() Data missing 'timestamp' field")
	}
	if _, ok := data["time"]; !ok {
		t.Error("CurrentTime() Data missing 'time' field")
	}
}

// TestKit_ExecuteCommand tests ExecuteCommand method
func TestKit_ExecuteCommand(t *testing.T) {
	kit := newTestKit(t)

	tests := []struct {
		name       string
		input      ExecuteCommandInput
		wantStatus Status
		wantCode   ErrorCode
	}{
		{
			name: "success - echo",
			input: ExecuteCommandInput{
				Command: "echo",
				Args:    []string{"hello"},
			},
			wantStatus: StatusSuccess,
		},
		{
			name: "dangerous command blocked",
			input: ExecuteCommandInput{
				Command: "rm",
				Args:    []string{"-rf", "/"},
			},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
		{
			name: "command not in whitelist",
			input: ExecuteCommandInput{
				Command: "nonexistent_command_12345",
				Args:    []string{},
			},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.ExecuteCommand(ctx, tt.input)

			if err != nil {
				t.Errorf("ExecuteCommand() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("ExecuteCommand() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("ExecuteCommand() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}

			// For success cases, verify output
			if tt.wantStatus == StatusSuccess && result.Data != nil {
				data, ok := result.Data.(map[string]any)
				if !ok {
					t.Error("ExecuteCommand() Data is not map[string]any")
					return
				}
				if _, ok := data["output"]; !ok {
					t.Error("ExecuteCommand() Data missing 'output' field")
				}
			}
		})
	}
}

// TestKit_GetEnv tests GetEnv method
func TestKit_GetEnv(t *testing.T) {
	kit := newTestKit(t)

	// Set test environment variable
	testKey := "TEST_ENV_VAR_KOOPA"
	testValue := "test_value"
	os.Setenv(testKey, testValue)
	defer os.Unsetenv(testKey)

	tests := []struct {
		name       string
		input      GetEnvInput
		wantStatus Status
		wantCode   ErrorCode
	}{
		{
			name:       "success",
			input:      GetEnvInput{Key: testKey},
			wantStatus: StatusSuccess,
		},
		{
			name:       "sensitive variable blocked",
			input:      GetEnvInput{Key: "API_KEY"},
			wantStatus: StatusError,
			wantCode:   ErrCodeSecurity,
		},
		{
			name:       "variable not set",
			input:      GetEnvInput{Key: "NONEXISTENT_VAR_12345"},
			wantStatus: StatusSuccess, // Not found is not an error, just empty value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.GetEnv(ctx, tt.input)

			if err != nil {
				t.Errorf("GetEnv() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("GetEnv() status = %v, want %v", result.Status, tt.wantStatus)
			}

			if tt.wantStatus == StatusError && result.Error != nil {
				if result.Error.Code != tt.wantCode {
					t.Errorf("GetEnv() error code = %v, want %v", result.Error.Code, tt.wantCode)
				}
			}
		})
	}
}

// ============================================================================
// Network Tool Tests
// ============================================================================

// TestKit_HTTPGet tests HTTPGet method
func TestKit_HTTPGet(t *testing.T) {
	t.Run("SSRF blocked", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		// Create mock HTTP validator that blocks all URLs
		mockHTTP := &mockHTTPValidator{
			validateErr: fmt.Errorf("SSRF blocked"),
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        mockHTTP,
			KnowledgeStore: &mockKnowledgeSearcherKit{},
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.HTTPGet(ctx, HTTPGetInput{URL: "http://localhost:8080"})

		if err != nil {
			t.Errorf("HTTPGet() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("HTTPGet() status = %v, want %v", result.Status, StatusError)
		}

		if result.Error == nil || result.Error.Code != ErrCodeSecurity {
			t.Errorf("HTTPGet() error code = %v, want %v", result.Error.Code, ErrCodeSecurity)
		}
	})

	t.Run("HTTP request failed", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		// Create mock HTTP validator that allows URLs but client returns error
		mockHTTP := &mockHTTPValidator{
			validateErr: nil, // Allow URL
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        mockHTTP,
			KnowledgeStore: &mockKnowledgeSearcherKit{},
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		// Use invalid URL to trigger network error
		result, err := kit.HTTPGet(ctx, HTTPGetInput{URL: "http://invalid-domain-that-does-not-exist-12345.com"})

		if err != nil {
			t.Errorf("HTTPGet() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("HTTPGet() status = %v, want %v", result.Status, StatusError)
		}

		if result.Error == nil || result.Error.Code != ErrCodeNetwork {
			t.Errorf("HTTPGet() error code = %v, want %v", result.Error.Code, ErrCodeNetwork)
		}
	})

	t.Run("success with small response", func(t *testing.T) {
		// Start test HTTP server
		testContent := "test response body"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(testContent))
		}))
		defer server.Close()

		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockHTTP := &mockHTTPValidator{
			validateErr: nil,
			maxSize:     5 * 1024 * 1024, // 5MB
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        mockHTTP,
			KnowledgeStore: &mockKnowledgeSearcherKit{},
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.HTTPGet(ctx, HTTPGetInput{URL: server.URL})

		if err != nil {
			t.Errorf("HTTPGet() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("HTTPGet() status = %v, want StatusSuccess", result.Status)
		}

		if result.Data != nil {
			data, ok := result.Data.(map[string]any)
			if !ok {
				t.Error("HTTPGet() Data is not map[string]any")
			} else {
				if body, ok := data["body"].(string); !ok || body != testContent {
					t.Errorf("HTTPGet() body = %v, want %v", body, testContent)
				}
				if status, ok := data["status"].(int); !ok || status != 200 {
					t.Errorf("HTTPGet() status = %v, want 200", status)
				}
			}
		}
	})

	t.Run("response size limit exceeded", func(t *testing.T) {
		// Start test HTTP server with large response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Write exactly maxSize + 1 bytes
			largeContent := make([]byte, 101)
			for i := range largeContent {
				largeContent[i] = 'A'
			}
			_, _ = w.Write(largeContent)
		}))
		defer server.Close()

		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockHTTP := &mockHTTPValidator{
			validateErr: nil,
			maxSize:     100, // Very small limit
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        mockHTTP,
			KnowledgeStore: &mockKnowledgeSearcherKit{},
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.HTTPGet(ctx, HTTPGetInput{URL: server.URL})

		if err != nil {
			t.Errorf("HTTPGet() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("HTTPGet() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil || result.Error.Code != ErrCodeIO {
			t.Errorf("HTTPGet() error code = %v, want ErrCodeIO", result.Error.Code)
		}
	})
}

// ============================================================================
// Knowledge Tool Tests
// ============================================================================

// mockKnowledgeSearcherWithResults is a mock that returns test results
type mockKnowledgeSearcherWithResults struct {
	results []knowledge.Result
	err     error
}

func (m *mockKnowledgeSearcherWithResults) Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error) {
	return m.results, m.err
}

// TestKit_SearchHistory tests SearchHistory method
func TestKit_SearchHistory(t *testing.T) {
	t.Run("success with results", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			results: []knowledge.Result{
				{
					Document: knowledge.Document{
						Content: "test conversation",
						Metadata: map[string]string{
							"session_id":  "test-session",
							"timestamp":   "2024-01-01T00:00:00Z",
							"turn_number": "1",
							"tool_count":  "2",
						},
					},
					Similarity: 0.95,
				},
			},
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchHistory(ctx, SearchHistoryInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchHistory() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("SearchHistory() status = %v, want StatusSuccess", result.Status)
		}
	})

	t.Run("search error", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			err: fmt.Errorf("search failed"),
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchHistory(ctx, SearchHistoryInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchHistory() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("SearchHistory() status = %v, want StatusError", result.Status)
		}
	})

	t.Run("empty results", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			results: []knowledge.Result{},
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchHistory(ctx, SearchHistoryInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchHistory() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("SearchHistory() status = %v, want StatusSuccess", result.Status)
		}
	})
}

// TestKit_SearchDocuments tests SearchDocuments method
func TestKit_SearchDocuments(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	mockKnowledge := &mockKnowledgeSearcherWithResults{
		results: []knowledge.Result{
			{
				Document: knowledge.Document{
					Content: "test document content",
					Metadata: map[string]string{
						"file_name": "test.md",
						"file_path": "/path/to/test.md",
					},
				},
				Similarity: 0.90,
			},
		},
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: mockKnowledge,
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	tests := []struct {
		name       string
		input      SearchDocumentsInput
		wantStatus Status
	}{
		{
			name: "success",
			input: SearchDocumentsInput{
				Query: "test query",
				TopK:  5,
			},
			wantStatus: StatusSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &ai.ToolContext{Context: context.Background()}
			result, err := kit.SearchDocuments(ctx, tt.input)

			if err != nil {
				t.Errorf("SearchDocuments() returned unexpected error: %v", err)
				return
			}

			if result.Status != tt.wantStatus {
				t.Errorf("SearchDocuments() status = %v, want %v", result.Status, tt.wantStatus)
			}
		})
	}
}

// TestKit_SearchSystemKnowledge tests SearchSystemKnowledge method
func TestKit_SearchSystemKnowledge(t *testing.T) {
	t.Run("success with results", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			results: []knowledge.Result{
				{
					Document: knowledge.Document{
						Content: "test system knowledge",
						Metadata: map[string]string{
							"knowledge_type": "best_practice",
							"topic":          "testing",
						},
					},
					Similarity: 0.88,
				},
			},
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchSystemKnowledge(ctx, SearchSystemKnowledgeInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchSystemKnowledge() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("SearchSystemKnowledge() status = %v, want %v", result.Status, StatusSuccess)
		}
	})

	t.Run("search error", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			err: fmt.Errorf("search failed"),
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchSystemKnowledge(ctx, SearchSystemKnowledgeInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchSystemKnowledge() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("SearchSystemKnowledge() status = %v, want StatusError", result.Status)
		}
	})

	t.Run("empty results", func(t *testing.T) {
		tmpDir := resolveSymlinks(t, t.TempDir())
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		mockKnowledge := &mockKnowledgeSearcherWithResults{
			results: []knowledge.Result{},
		}

		cfg := KitConfig{
			PathVal:        pathVal,
			CmdVal:         security.NewCommand(),
			EnvVal:         security.NewEnv(),
			HTTPVal:        &mockHTTPValidator{},
			KnowledgeStore: mockKnowledge,
		}

		kit, err := NewKit(cfg)
		if err != nil {
			t.Fatalf("failed to create kit: %v", err)
		}

		ctx := &ai.ToolContext{Context: context.Background()}
		result, err := kit.SearchSystemKnowledge(ctx, SearchSystemKnowledgeInput{
			Query: "test query",
			TopK:  3,
		})

		if err != nil {
			t.Errorf("SearchSystemKnowledge() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("SearchSystemKnowledge() status = %v, want StatusSuccess", result.Status)
		}
	})
}

// ============================================================================
// Additional Coverage Tests for Low-Coverage Functions
// ============================================================================

// TestKit_ExecuteCommand_ExecutionFailure tests command execution failures
func TestKit_ExecuteCommand_ExecutionFailure(t *testing.T) {
	kit := newTestKit(t)

	t.Run("command fails with exit code", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		// Use 'grep' with invalid pattern to cause execution failure
		result, err := kit.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "grep",
			Args:    []string{"--invalid-option-xyz"},
		})

		if err != nil {
			t.Errorf("ExecuteCommand() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("ExecuteCommand() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil {
			t.Error("ExecuteCommand() Error is nil, want error")
			return
		}

		if result.Error.Code != ErrCodeExecution {
			t.Errorf("ExecuteCommand() error code = %v, want %v", result.Error.Code, ErrCodeExecution)
		}
	})

	t.Run("successful command execution with output", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		// Test successful execution with 'pwd' command
		result, err := kit.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "pwd",
			Args:    []string{},
		})

		if err != nil {
			t.Errorf("ExecuteCommand() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("ExecuteCommand() status = %v, want StatusSuccess", result.Status)
		}

		if result.Data == nil {
			t.Error("ExecuteCommand() Data is nil, want data")
			return
		}

		data, ok := result.Data.(map[string]any)
		if !ok {
			t.Error("ExecuteCommand() Data is not map[string]any")
			return
		}

		output, ok := data["output"]
		if !ok {
			t.Error("ExecuteCommand() Data missing 'output' field")
			return
		}

		outputStr, ok := output.(string)
		if !ok || outputStr == "" {
			t.Error("ExecuteCommand() output is empty or not string")
		}
	})
}

// TestKit_DeleteFile_EdgeCases tests DeleteFile edge cases
func TestKit_DeleteFile_EdgeCases(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	t.Run("file not found", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		nonExistentFile := filepath.Join(tmpDir, "nonexistent.txt")

		result, err := kit.DeleteFile(ctx, DeleteFileInput{Path: nonExistentFile})

		if err != nil {
			t.Errorf("DeleteFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("DeleteFile() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil {
			t.Error("DeleteFile() Error is nil, want error")
			return
		}

		if result.Error.Code != ErrCodeNotFound {
			t.Errorf("DeleteFile() error code = %v, want %v", result.Error.Code, ErrCodeNotFound)
		}
	})

	t.Run("security validation failure", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}

		result, err := kit.DeleteFile(ctx, DeleteFileInput{Path: "../../etc/passwd"})

		if err != nil {
			t.Errorf("DeleteFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("DeleteFile() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil {
			t.Error("DeleteFile() Error is nil, want error")
			return
		}

		if result.Error.Code != ErrCodeSecurity {
			t.Errorf("DeleteFile() error code = %v, want %v", result.Error.Code, ErrCodeSecurity)
		}
	})
}

// TestKit_ReadFile_EdgeCases tests ReadFile edge cases
func TestKit_ReadFile_EdgeCases(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	t.Run("file not found", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		nonExistentFile := filepath.Join(tmpDir, "nonexistent.txt")

		result, err := kit.ReadFile(ctx, ReadFileInput{Path: nonExistentFile})

		if err != nil {
			t.Errorf("ReadFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("ReadFile() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil {
			t.Error("ReadFile() Error is nil, want error")
			return
		}

		if result.Error.Code != ErrCodeNotFound {
			t.Errorf("ReadFile() error code = %v, want %v", result.Error.Code, ErrCodeNotFound)
		}
	})

	t.Run("security validation failure", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}

		result, err := kit.ReadFile(ctx, ReadFileInput{Path: "../../etc/passwd"})

		if err != nil {
			t.Errorf("ReadFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusError {
			t.Errorf("ReadFile() status = %v, want StatusError", result.Status)
		}

		if result.Error == nil {
			t.Error("ReadFile() Error is nil, want error")
			return
		}

		if result.Error.Code != ErrCodeSecurity {
			t.Errorf("ReadFile() error code = %v, want %v", result.Error.Code, ErrCodeSecurity)
		}
	})
}

// TestKit_Register_MultipleTools tests that Register registers all expected tools
func TestKit_Register_MultipleTools(t *testing.T) {
	kit := newTestKit(t)
	ctx := context.Background()
	g := genkit.Init(ctx)

	err := kit.Register(g)
	if err != nil {
		t.Fatalf("Register() error = %v, want nil", err)
	}

	// Verify all 12 tools are registered
	expectedTools := []string{
		"currentTime",
		"readFile",
		"writeFile",
		"listFiles",
		"deleteFile",
		"executeCommand",
		"httpGet",
		"getEnv",
		"getFileInfo",
		"searchHistory",
		"searchDocuments",
		"searchSystemKnowledge",
	}

	for _, toolName := range expectedTools {
		if tool := genkit.LookupTool(g, toolName); tool == nil {
			t.Errorf("Tool %q not registered", toolName)
		}
	}
}

// TestKit_ListFiles_EmptyDirectory tests ListFiles on an empty directory
func TestKit_ListFiles_EmptyDirectory(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.Mkdir(emptyDir, 0750); err != nil {
		t.Fatalf("failed to create empty directory: %v", err)
	}

	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}
	result, err := kit.ListFiles(ctx, ListFilesInput{Path: emptyDir})

	if err != nil {
		t.Errorf("ListFiles() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("ListFiles() status = %v, want StatusSuccess", result.Status)
	}

	if result.Data != nil {
		data, ok := result.Data.(map[string]any)
		if !ok {
			t.Error("ListFiles() Data is not map[string]any")
			return
		}
		entries, ok := data["entries"]
		if !ok {
			t.Error("ListFiles() Data missing 'entries' field")
			return
		}
		entriesList, ok := entries.([]map[string]any)
		if !ok {
			t.Error("ListFiles() entries is not []map[string]any")
			return
		}
		if len(entriesList) != 0 {
			t.Errorf("ListFiles() entries count = %d, want 0 for empty directory", len(entriesList))
		}
	}
}

// TestKit_GetFileInfo_Directory tests GetFileInfo on a directory
func TestKit_GetFileInfo_Directory(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	testDir := filepath.Join(tmpDir, "testdir")
	if err := os.Mkdir(testDir, 0750); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}
	result, err := kit.GetFileInfo(ctx, GetFileInfoInput{Path: testDir})

	if err != nil {
		t.Errorf("GetFileInfo() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("GetFileInfo() status = %v, want StatusSuccess", result.Status)
	}

	if result.Data != nil {
		data, ok := result.Data.(map[string]any)
		if !ok {
			t.Error("GetFileInfo() Data is not map[string]any")
			return
		}
		isDir, ok := data["is_dir"]
		if !ok {
			t.Error("GetFileInfo() Data missing 'is_dir' field")
			return
		}
		isDirBool, ok := isDir.(bool)
		if !ok {
			t.Error("GetFileInfo() 'is_dir' is not bool")
			return
		}
		if !isDirBool {
			t.Error("GetFileInfo() 'is_dir' = false, want true for directory")
		}
	}
}

// TestKit_WriteFile_Success tests successful WriteFile scenarios
func TestKit_WriteFile_Success(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	t.Run("write to new file", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		testFile := filepath.Join(tmpDir, "newfile.txt")
		testContent := "test content"

		result, err := kit.WriteFile(ctx, WriteFileInput{
			Path:    testFile,
			Content: testContent,
		})

		if err != nil {
			t.Errorf("WriteFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("WriteFile() status = %v, want StatusSuccess", result.Status)
		}

		// Verify file was written
		content, err := os.ReadFile(testFile)
		if err != nil {
			t.Errorf("Failed to read written file: %v", err)
			return
		}
		if string(content) != testContent {
			t.Errorf("File content = %q, want %q", string(content), testContent)
		}
	})

	t.Run("overwrite existing file", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		testFile := filepath.Join(tmpDir, "existing.txt")

		// Create initial file
		if err := os.WriteFile(testFile, []byte("old content"), 0600); err != nil {
			t.Fatalf("failed to create initial file: %v", err)
		}

		newContent := "new content"
		result, err := kit.WriteFile(ctx, WriteFileInput{
			Path:    testFile,
			Content: newContent,
		})

		if err != nil {
			t.Errorf("WriteFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("WriteFile() status = %v, want StatusSuccess", result.Status)
		}

		// Verify file was overwritten
		content, err := os.ReadFile(testFile)
		if err != nil {
			t.Errorf("Failed to read written file: %v", err)
			return
		}
		if string(content) != newContent {
			t.Errorf("File content = %q, want %q", string(content), newContent)
		}
	})

	t.Run("create nested directories", func(t *testing.T) {
		ctx := &ai.ToolContext{Context: context.Background()}
		testFile := filepath.Join(tmpDir, "subdir1", "subdir2", "file.txt")
		testContent := "nested content"

		result, err := kit.WriteFile(ctx, WriteFileInput{
			Path:    testFile,
			Content: testContent,
		})

		if err != nil {
			t.Errorf("WriteFile() returned unexpected error: %v", err)
			return
		}

		if result.Status != StatusSuccess {
			t.Errorf("WriteFile() status = %v, want StatusSuccess", result.Status)
		}

		// Verify file was written
		content, err := os.ReadFile(testFile)
		if err != nil {
			t.Errorf("Failed to read written file: %v", err)
			return
		}
		if string(content) != testContent {
			t.Errorf("File content = %q, want %q", string(content), testContent)
		}
	})
}

// TestKit_DeleteFile_Success tests successful DeleteFile scenarios
func TestKit_DeleteFile_Success(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}
	testFile := filepath.Join(tmpDir, "to_delete.txt")

	// Create test file
	if err := os.WriteFile(testFile, []byte("delete me"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	result, err := kit.DeleteFile(ctx, DeleteFileInput{Path: testFile})

	if err != nil {
		t.Errorf("DeleteFile() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("DeleteFile() status = %v, want StatusSuccess", result.Status)
	}

	// Verify file was deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Errorf("File still exists after deletion")
	}
}

// TestKit_ReadFile_Success tests successful ReadFile scenarios
func TestKit_ReadFile_Success(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}
	testFile := filepath.Join(tmpDir, "read_test.txt")
	testContent := "test content to read"

	// Create test file
	if err := os.WriteFile(testFile, []byte(testContent), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	result, err := kit.ReadFile(ctx, ReadFileInput{Path: testFile})

	if err != nil {
		t.Errorf("ReadFile() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("ReadFile() status = %v, want StatusSuccess", result.Status)
	}

	if result.Data != nil {
		data, ok := result.Data.(map[string]any)
		if !ok {
			t.Error("ReadFile() Data is not map[string]any")
			return
		}
		content, ok := data["content"]
		if !ok {
			t.Error("ReadFile() Data missing 'content' field")
			return
		}
		contentStr, ok := content.(string)
		if !ok {
			t.Error("ReadFile() content is not string")
			return
		}
		if contentStr != testContent {
			t.Errorf("ReadFile() content = %q, want %q", contentStr, testContent)
		}
	}
}

// TestMockHTTPValidator_Coverage tests mock HTTP validator methods for coverage
func TestMockHTTPValidator_Coverage(t *testing.T) {
	t.Run("Client with nil", func(t *testing.T) {
		mock := &mockHTTPValidator{
			client: nil,
		}
		client := mock.Client()
		if client == nil {
			t.Error("Client() returned nil, want default client")
		}
	})

	t.Run("Client with custom client", func(t *testing.T) {
		customClient := &http.Client{}
		mock := &mockHTTPValidator{
			client: customClient,
		}
		client := mock.Client()
		if client != customClient {
			t.Error("Client() returned different client")
		}
	})

	t.Run("MaxResponseSize with zero", func(t *testing.T) {
		mock := &mockHTTPValidator{
			maxSize: 0,
		}
		size := mock.MaxResponseSize()
		expectedDefault := int64(5 * 1024 * 1024)
		if size != expectedDefault {
			t.Errorf("MaxResponseSize() = %d, want %d (default)", size, expectedDefault)
		}
	})

	t.Run("MaxResponseSize with custom size", func(t *testing.T) {
		customSize := int64(1024)
		mock := &mockHTTPValidator{
			maxSize: customSize,
		}
		size := mock.MaxResponseSize()
		if size != customSize {
			t.Errorf("MaxResponseSize() = %d, want %d", size, customSize)
		}
	})
}

// TestKit_NewKit_ValidationErrors tests NewKit validation errors
func TestKit_NewKit_ValidationErrors(t *testing.T) {
	validPathVal, _ := security.NewPath([]string{"/tmp"})
	validCmdVal := security.NewCommand()
	validEnvVal := security.NewEnv()
	validHTTPVal := &mockHTTPValidator{}
	validKnowledge := &mockKnowledgeSearcherKit{}

	tests := []struct {
		name    string
		cfg     KitConfig
		wantErr string
	}{
		{
			name: "missing PathVal",
			cfg: KitConfig{
				PathVal:        nil,
				CmdVal:         validCmdVal,
				EnvVal:         validEnvVal,
				HTTPVal:        validHTTPVal,
				KnowledgeStore: validKnowledge,
			},
			wantErr: "PathVal is required",
		},
		{
			name: "missing CmdVal",
			cfg: KitConfig{
				PathVal:        validPathVal,
				CmdVal:         nil,
				EnvVal:         validEnvVal,
				HTTPVal:        validHTTPVal,
				KnowledgeStore: validKnowledge,
			},
			wantErr: "CmdVal is required",
		},
		{
			name: "missing EnvVal",
			cfg: KitConfig{
				PathVal:        validPathVal,
				CmdVal:         validCmdVal,
				EnvVal:         nil,
				HTTPVal:        validHTTPVal,
				KnowledgeStore: validKnowledge,
			},
			wantErr: "EnvVal is required",
		},
		{
			name: "missing HTTPVal",
			cfg: KitConfig{
				PathVal:        validPathVal,
				CmdVal:         validCmdVal,
				EnvVal:         validEnvVal,
				HTTPVal:        nil,
				KnowledgeStore: validKnowledge,
			},
			wantErr: "HTTPVal is required",
		},
		{
			name: "missing KnowledgeStore",
			cfg: KitConfig{
				PathVal:        validPathVal,
				CmdVal:         validCmdVal,
				EnvVal:         validEnvVal,
				HTTPVal:        validHTTPVal,
				KnowledgeStore: nil,
			},
			wantErr: "KnowledgeStore is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKit(tt.cfg)
			if err == nil {
				t.Error("NewKit() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewKit() error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestKit_WithLogger tests WithLogger option
func TestKit_WithLogger(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	logger := &mockLogger{}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("failed to create kit with logger: %v", err)
	}

	// Register tools (should log)
	ctx := context.Background()
	g := genkit.Init(ctx)
	err = kit.Register(g)
	if err != nil {
		t.Errorf("Register() error = %v, want nil", err)
	}

	// Verify logger was called
	if len(logger.logs) == 0 {
		t.Error("Logger was not called during Register")
	}

	// Call a method that logs (like CurrentTime)
	toolCtx := &ai.ToolContext{Context: context.Background()}
	_, err = kit.CurrentTime(toolCtx, CurrentTimeInput{})
	if err != nil {
		t.Errorf("CurrentTime() error = %v, want nil", err)
	}

	// Verify more log calls were made
	if len(logger.logs) < 2 {
		t.Errorf("Logger calls = %d, want at least 2", len(logger.logs))
	}
}

// TestKit_ListFiles_MultipleEntries tests ListFiles with multiple files
func TestKit_ListFiles_MultipleEntries(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Create multiple files and directories
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test1"), 0600); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("test2"), 0600); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}
	if err := os.Mkdir(filepath.Join(tmpDir, "subdir"), 0750); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}
	result, err := kit.ListFiles(ctx, ListFilesInput{Path: tmpDir})

	if err != nil {
		t.Errorf("ListFiles() returned unexpected error: %v", err)
		return
	}

	if result.Status != StatusSuccess {
		t.Errorf("ListFiles() status = %v, want StatusSuccess", result.Status)
	}

	if result.Data != nil {
		data, ok := result.Data.(map[string]any)
		if !ok {
			t.Error("ListFiles() Data is not map[string]any")
			return
		}
		entries, ok := data["entries"]
		if !ok {
			t.Error("ListFiles() Data missing 'entries' field")
			return
		}
		entriesList, ok := entries.([]map[string]any)
		if !ok {
			t.Error("ListFiles() entries is not []map[string]any")
			return
		}
		if len(entriesList) != 3 {
			t.Errorf("ListFiles() entries count = %d, want 3 (2 files + 1 dir)", len(entriesList))
		}
	}
}
