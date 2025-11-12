package rag

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/koopa0/koopa-cli/internal/knowledge"
)

// ============================================================================
// Mock Implementation
// ============================================================================

// mockIndexerStore implements IndexerStore for testing
type mockIndexerStore struct {
	// Error configuration
	addErr              error
	listBySourceTypeErr error
	deleteErr           error

	// Return values
	listBySourceTypeResult []knowledge.Document

	// Call tracking
	addCalls              int
	listBySourceTypeCalls int
	deleteCalls           int
	lastAddedDoc          knowledge.Document
	lastListSourceType    string
	lastDeletedID         string
}

func (m *mockIndexerStore) Add(ctx context.Context, doc knowledge.Document) error {
	m.addCalls++
	m.lastAddedDoc = doc
	return m.addErr
}

func (m *mockIndexerStore) ListBySourceType(ctx context.Context, sourceType string, limit int) ([]knowledge.Document, error) {
	m.listBySourceTypeCalls++
	m.lastListSourceType = sourceType
	if m.listBySourceTypeErr != nil {
		return nil, m.listBySourceTypeErr
	}
	return m.listBySourceTypeResult, nil
}

func (m *mockIndexerStore) Delete(ctx context.Context, docID string) error {
	m.deleteCalls++
	m.lastDeletedID = docID
	return m.deleteErr
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewIndexer(t *testing.T) {
	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	if indexer == nil {
		t.Fatal("NewIndexer returned nil")
		return
	}

	if indexer.store != mockStore {
		t.Error("store not set correctly")
	}
}

// ============================================================================
// Indexer.AddFile Tests
// ============================================================================

func TestIndexer_AddFile_Success(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "This is test content for indexing"

	if err := os.WriteFile(testFile, []byte(testContent), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	err := indexer.AddFile(context.Background(), testFile)
	if err != nil {
		t.Fatalf("AddFile failed: %v", err)
	}

	// Verify store.Add was called
	if mockStore.addCalls != 1 {
		t.Errorf("expected 1 Add call, got %d", mockStore.addCalls)
	}

	// Verify document content
	doc := mockStore.lastAddedDoc
	if doc.Content != testContent {
		t.Errorf("content mismatch: got %q, want %q", doc.Content, testContent)
	}

	// Verify metadata
	if doc.Metadata["source_type"] != "file" {
		t.Error("source_type should be 'file'")
	}

	if doc.Metadata["file_name"] != "test.txt" {
		t.Errorf("file_name mismatch: got %q", doc.Metadata["file_name"])
	}

	if doc.Metadata["file_ext"] != ".txt" {
		t.Errorf("file_ext mismatch: got %q", doc.Metadata["file_ext"])
	}

	// Verify document ID is generated
	if doc.ID == "" {
		t.Error("document ID should not be empty")
	}

	if doc.ID[:5] != "file_" {
		t.Errorf("document ID should start with 'file_', got %q", doc.ID)
	}
}

func TestIndexer_AddFile_DirectoryError(t *testing.T) {
	tmpDir := t.TempDir()

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	err := indexer.AddFile(context.Background(), tmpDir)
	if err == nil {
		t.Fatal("expected error for directory, got nil")
	}

	if !contains(err.Error(), "directory") {
		t.Errorf("error should mention directory: %v", err)
	}

	// Verify store.Add was not called
	if mockStore.addCalls > 0 {
		t.Error("store.Add should not be called for directory")
	}
}

func TestIndexer_AddFile_UnsupportedExtension(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(testFile, []byte("binary"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	err := indexer.AddFile(context.Background(), testFile)
	if err == nil {
		t.Fatal("expected error for unsupported extension, got nil")
	}

	if !contains(err.Error(), "unsupported file type") {
		t.Errorf("error should mention unsupported file type: %v", err)
	}

	// Verify store.Add was not called
	if mockStore.addCalls > 0 {
		t.Error("store.Add should not be called for unsupported file")
	}
}

func TestIndexer_AddFile_NonExistentFile(t *testing.T) {
	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	err := indexer.AddFile(context.Background(), "/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	// Should fail before calling store.Add
	if mockStore.addCalls > 0 {
		t.Error("store.Add should not be called for non-existent file")
	}
}

func TestIndexer_AddFile_StoreError(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")

	if err := os.WriteFile(testFile, []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mockStore := &mockIndexerStore{
		addErr: errors.New("database connection lost"),
	}
	indexer := NewIndexer(mockStore)

	err := indexer.AddFile(context.Background(), testFile)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "failed to add document to store") {
		t.Errorf("unexpected error: %v", err)
	}

	if !contains(err.Error(), "database connection lost") {
		t.Errorf("error should wrap original error: %v", err)
	}
}

// ============================================================================
// Indexer.AddDirectory Tests
// ============================================================================

func TestIndexer_AddDirectory_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	files := []struct {
		name    string
		content string
	}{
		{"file1.txt", "content 1"},
		{"file2.md", "# Markdown content"},
		{"code.go", "package main"},
		{"subdir/nested.py", "print('hello')"},
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f.name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(f.content), 0600); err != nil {
			t.Fatalf("failed to create file %s: %v", f.name, err)
		}
	}

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	result, err := indexer.AddDirectory(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("AddDirectory failed: %v", err)
	}

	// Should add 4 files
	if result.FilesAdded != 4 {
		t.Errorf("expected 4 files added, got %d", result.FilesAdded)
	}

	if mockStore.addCalls != 4 {
		t.Errorf("expected 4 Add calls, got %d", mockStore.addCalls)
	}

	// Check duration is recorded
	if result.Duration == 0 {
		t.Error("duration should be recorded")
	}

	// Check total size is calculated
	if result.TotalSize == 0 {
		t.Error("total size should be calculated")
	}
}

func TestIndexer_AddDirectory_WithGitignore(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .gitignore
	gitignoreContent := "*.log\nnode_modules/\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".gitignore"), []byte(gitignoreContent), 0600); err != nil {
		t.Fatalf("failed to create .gitignore: %v", err)
	}

	// Create files (some should be ignored)
	files := []struct {
		name          string
		content       string
		shouldBeAdded bool
	}{
		{"file1.txt", "content 1", true},
		{"debug.log", "log content", false},      // Ignored by .gitignore
		{"node_modules/lib.js", "module", false}, // Ignored directory
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f.name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(f.content), 0600); err != nil {
			t.Fatalf("failed to create file %s: %v", f.name, err)
		}
	}

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	result, err := indexer.AddDirectory(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("AddDirectory failed: %v", err)
	}

	// Should only add files not in .gitignore
	// Note: .gitignore itself is also skipped (unsupported extension)
	if result.FilesAdded != 1 {
		t.Errorf("expected 1 file added, got %d", result.FilesAdded)
	}

	// 3 files skipped: debug.log (gitignore), node_modules/lib.js (gitignore), .gitignore (unsupported ext)
	if result.FilesSkipped != 3 {
		t.Errorf("expected 3 files skipped, got %d", result.FilesSkipped)
	}
}

func TestIndexer_AddDirectory_SkipsUnsupportedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files with various extensions
	files := map[string]bool{
		"code.go":    true,  // Supported
		"readme.md":  true,  // Supported
		"binary.exe": false, // Unsupported
		"image.png":  false, // Unsupported
		"data.csv":   false, // Unsupported
	}

	for name := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte("content"), 0600); err != nil {
			t.Fatalf("failed to create file %s: %v", name, err)
		}
	}

	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	result, err := indexer.AddDirectory(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("AddDirectory failed: %v", err)
	}

	if result.FilesAdded != 2 {
		t.Errorf("expected 2 files added, got %d", result.FilesAdded)
	}

	if result.FilesSkipped != 3 {
		t.Errorf("expected 3 files skipped, got %d", result.FilesSkipped)
	}
}

func TestIndexer_AddDirectory_StoreError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create one file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mockStore := &mockIndexerStore{
		addErr: errors.New("database error"),
	}
	indexer := NewIndexer(mockStore)

	result, err := indexer.AddDirectory(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("AddDirectory should not fail on individual file errors: %v", err)
	}

	// File should be counted as failed
	if result.FilesFailed != 1 {
		t.Errorf("expected 1 file failed, got %d", result.FilesFailed)
	}

	if result.FilesAdded != 0 {
		t.Errorf("expected 0 files added, got %d", result.FilesAdded)
	}
}

func TestIndexer_AddDirectory_NonExistent(t *testing.T) {
	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	_, err := indexer.AddDirectory(context.Background(), "/nonexistent/directory")
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
}

// ============================================================================
// Indexer.ListDocuments Tests
// ============================================================================

func TestIndexer_ListDocuments_Success(t *testing.T) {
	mockDocs := []knowledge.Document{
		{
			ID:      "doc1",
			Content: "content 1",
			Metadata: map[string]string{
				"source_type": "file",
				"file_name":   "test1.txt",
			},
		},
		{
			ID:      "doc2",
			Content: "content 2",
			Metadata: map[string]string{
				"source_type": "file",
				"file_name":   "test2.md",
			},
		},
	}

	mockStore := &mockIndexerStore{
		listBySourceTypeResult: mockDocs,
	}
	indexer := NewIndexer(mockStore)

	docs, err := indexer.ListDocuments(context.Background())
	if err != nil {
		t.Fatalf("ListDocuments failed: %v", err)
	}

	if len(docs) != 2 {
		t.Errorf("expected 2 documents, got %d", len(docs))
	}

	// Verify correct source type was queried
	if mockStore.lastListSourceType != "file" {
		t.Errorf("expected source_type='file', got %q", mockStore.lastListSourceType)
	}

	// Verify document content
	if docs[0].ID != "doc1" {
		t.Errorf("first doc ID mismatch: got %q", docs[0].ID)
	}
}

func TestIndexer_ListDocuments_Error(t *testing.T) {
	mockStore := &mockIndexerStore{
		listBySourceTypeErr: errors.New("database connection lost"),
	}
	indexer := NewIndexer(mockStore)

	_, err := indexer.ListDocuments(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "failed to list documents") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIndexer_ListDocuments_Empty(t *testing.T) {
	mockStore := &mockIndexerStore{
		listBySourceTypeResult: []knowledge.Document{},
	}
	indexer := NewIndexer(mockStore)

	docs, err := indexer.ListDocuments(context.Background())
	if err != nil {
		t.Fatalf("ListDocuments failed: %v", err)
	}

	if len(docs) != 0 {
		t.Errorf("expected 0 documents, got %d", len(docs))
	}
}

// ============================================================================
// Indexer.RemoveDocument Tests
// ============================================================================

func TestIndexer_RemoveDocument_Success(t *testing.T) {
	mockStore := &mockIndexerStore{}
	indexer := NewIndexer(mockStore)

	err := indexer.RemoveDocument(context.Background(), "doc-123")
	if err != nil {
		t.Fatalf("RemoveDocument failed: %v", err)
	}

	if mockStore.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", mockStore.deleteCalls)
	}

	if mockStore.lastDeletedID != "doc-123" {
		t.Errorf("wrong document ID deleted: got %q", mockStore.lastDeletedID)
	}
}

func TestIndexer_RemoveDocument_Error(t *testing.T) {
	mockStore := &mockIndexerStore{
		deleteErr: errors.New("document not found"),
	}
	indexer := NewIndexer(mockStore)

	err := indexer.RemoveDocument(context.Background(), "missing-doc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "document not found") {
		t.Errorf("error should wrap original error: %v", err)
	}
}

// ============================================================================
// Indexer.GetStats Tests
// ============================================================================

func TestIndexer_GetStats_Success(t *testing.T) {
	mockDocs := []knowledge.Document{
		{
			ID:      "doc1",
			Content: "content 1",
			Metadata: map[string]string{
				"file_ext":  ".txt",
				"file_size": "1024",
			},
		},
		{
			ID:      "doc2",
			Content: "content 2",
			Metadata: map[string]string{
				"file_ext":  ".md",
				"file_size": "2048",
			},
		},
		{
			ID:      "doc3",
			Content: "content 3",
			Metadata: map[string]string{
				"file_ext":  ".txt",
				"file_size": "512",
			},
		},
	}

	mockStore := &mockIndexerStore{
		listBySourceTypeResult: mockDocs,
	}
	indexer := NewIndexer(mockStore)

	stats, err := indexer.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Check total documents
	if totalDocs := stats["total_documents"].(int); totalDocs != 3 {
		t.Errorf("expected 3 total documents, got %d", totalDocs)
	}

	// Check file types count
	fileTypes := stats["file_types"].(map[string]int)
	if fileTypes[".txt"] != 2 {
		t.Errorf("expected 2 .txt files, got %d", fileTypes[".txt"])
	}
	if fileTypes[".md"] != 1 {
		t.Errorf("expected 1 .md file, got %d", fileTypes[".md"])
	}

	// Check total size (1024 + 2048 + 512 = 3584)
	if totalSize := stats["total_size"].(int64); totalSize != 3584 {
		t.Errorf("expected total size 3584, got %d", totalSize)
	}
}

func TestIndexer_GetStats_Empty(t *testing.T) {
	mockStore := &mockIndexerStore{
		listBySourceTypeResult: []knowledge.Document{},
	}
	indexer := NewIndexer(mockStore)

	stats, err := indexer.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if totalDocs := stats["total_documents"].(int); totalDocs != 0 {
		t.Errorf("expected 0 total documents, got %d", totalDocs)
	}
}

func TestIndexer_GetStats_ListError(t *testing.T) {
	mockStore := &mockIndexerStore{
		listBySourceTypeErr: errors.New("database error"),
	}
	indexer := NewIndexer(mockStore)

	stats, err := indexer.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats should not fail on list error: %v", err)
	}

	// Should return empty stats
	if totalDocs := stats["total_documents"].(int); totalDocs != 0 {
		t.Errorf("expected 0 total documents on error, got %d", totalDocs)
	}
}

func TestIndexer_GetStats_InvalidFileSize(t *testing.T) {
	mockDocs := []knowledge.Document{
		{
			ID:      "doc1",
			Content: "content",
			Metadata: map[string]string{
				"file_ext":  ".txt",
				"file_size": "invalid", // Invalid size
			},
		},
	}

	mockStore := &mockIndexerStore{
		listBySourceTypeResult: mockDocs,
	}
	indexer := NewIndexer(mockStore)

	stats, err := indexer.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Should skip invalid size
	if totalSize := stats["total_size"].(int64); totalSize != 0 {
		t.Errorf("expected total size 0 (invalid size skipped), got %d", totalSize)
	}
}

// ============================================================================
// generateDocID Tests
// ============================================================================

func TestGenerateDocID(t *testing.T) {
	tests := []struct {
		name     string
		path1    string
		path2    string
		samePath bool
	}{
		{
			name:     "same absolute path",
			path1:    "/tmp/test.txt",
			path2:    "/tmp/test.txt",
			samePath: true,
		},
		{
			name:     "different paths",
			path1:    "/tmp/file1.txt",
			path2:    "/tmp/file2.txt",
			samePath: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := generateDocID(tt.path1)
			id2 := generateDocID(tt.path2)

			// All IDs should start with "file_"
			if id1[:5] != "file_" || id2[:5] != "file_" {
				t.Error("document IDs should start with 'file_'")
			}

			// All IDs should have consistent length (file_ + 32 hex chars = 37)
			if len(id1) != 37 || len(id2) != 37 {
				t.Errorf("document ID length should be 37, got %d and %d", len(id1), len(id2))
			}

			if tt.samePath {
				if id1 != id2 {
					t.Errorf("same path should generate same ID: %q != %q", id1, id2)
				}
			} else {
				if id1 == id2 {
					t.Errorf("different paths should generate different IDs")
				}
			}
		})
	}
}

// ============================================================================
// SupportedExtensions Tests
// ============================================================================

func TestSupportedExtensions(t *testing.T) {
	// Verify common extensions are supported
	expectedSupported := []string{
		".txt", ".md", ".go", ".py", ".js", ".ts",
		".java", ".c", ".cpp", ".rs", ".sh",
		".yaml", ".yml", ".json",
	}

	for _, ext := range expectedSupported {
		if !SupportedExtensions[ext] {
			t.Errorf("extension %s should be supported", ext)
		}
	}

	// Verify unsupported extensions
	unsupported := []string{".exe", ".bin", ".pdf", ".docx", ".zip"}
	for _, ext := range unsupported {
		if SupportedExtensions[ext] {
			t.Errorf("extension %s should not be supported", ext)
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
