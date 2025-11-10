package rag

// indexer.go implements local file indexing for RAG.
//
// Provides functionality to:
//   - Add files or directories to the knowledge store
//   - Extract text content from various file types
//   - Generate document IDs and metadata
//   - List all indexed documents
//   - Remove documents from the knowledge store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koopa0/koopa/internal/knowledge"
)

// SupportedExtensions are file types we can index
var SupportedExtensions = map[string]bool{
	".txt":  true,
	".md":   true,
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".java": true,
	".c":    true,
	".cpp":  true,
	".h":    true,
	".hpp":  true,
	".rs":   true,
	".rb":   true,
	".php":  true,
	".sh":   true,
	".yaml": true,
	".yml":  true,
	".json": true,
	".xml":  true,
	".html": true,
	".css":  true,
	".sql":  true,
}

// IndexResult represents the result of an indexing operation
type IndexResult struct {
	FilesAdded   int
	FilesSkipped int
	FilesFailed  int
	TotalSize    int64
	Duration     time.Duration
}

// Indexer handles local file indexing
type Indexer struct {
	store *knowledge.Store
}

// NewIndexer creates a new file indexer
func NewIndexer(store *knowledge.Store) *Indexer {
	return &Indexer{store: store}
}

// AddFile adds a single file to the knowledge store
func (idx *Indexer) AddFile(ctx context.Context, filePath string) error {
	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, use AddDirectory instead")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if !SupportedExtensions[ext] {
		return fmt.Errorf("unsupported file type: %s", ext)
	}

	// Read file content
	// #nosec G304 -- filePath is validated via os.Stat and extension check above
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Generate document ID from file path
	docID := generateDocID(filePath)

	// Create knowledge document
	doc := knowledge.Document{
		ID:      docID,
		Content: string(content),
		Metadata: map[string]string{
			"source_type": "file",
			"file_path":   filePath,
			"file_name":   filepath.Base(filePath),
			"file_ext":    ext,
			"file_size":   fmt.Sprintf("%d", info.Size()),
			"indexed_at":  time.Now().Format(time.RFC3339),
		},
		CreateAt: time.Now(),
	}

	// Add to knowledge store
	if err := idx.store.Add(ctx, doc); err != nil {
		return fmt.Errorf("failed to add document to store: %w", err)
	}

	return nil
}

// AddDirectory recursively adds all supported files in a directory
func (idx *Indexer) AddDirectory(ctx context.Context, dirPath string) (*IndexResult, error) {
	startTime := time.Now()
	result := &IndexResult{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			result.FilesFailed++
			return nil // Continue walking even if one file fails
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file type is supported
		ext := strings.ToLower(filepath.Ext(path))
		if !SupportedExtensions[ext] {
			result.FilesSkipped++
			return nil
		}

		// Try to add the file
		if err := idx.AddFile(ctx, path); err != nil {
			result.FilesFailed++
			return nil // Continue walking
		}

		result.FilesAdded++
		result.TotalSize += info.Size()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// ListDocuments returns all indexed documents
func (idx *Indexer) ListDocuments(ctx context.Context) ([]knowledge.Document, error) {
	// Use ListBySourceType to get all file documents without needing embeddings
	docs, err := idx.store.ListBySourceType(ctx, "file", 1000)
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}

	return docs, nil
}

// RemoveDocument removes a document by ID
func (idx *Indexer) RemoveDocument(ctx context.Context, docID string) error {
	return idx.store.Delete(ctx, docID)
}

// GetStats returns statistics about indexed documents
func (idx *Indexer) GetStats(ctx context.Context) (map[string]any, error) {
	docs, err := idx.ListDocuments(ctx)
	if err != nil {
		// If no documents or error, return empty stats
		return map[string]any{
			"total_documents": 0,
			"file_types":      make(map[string]int),
			"total_size":      int64(0),
		}, nil
	}

	stats := map[string]any{
		"total_documents": len(docs),
		"file_types":      make(map[string]int),
		"total_size":      int64(0),
	}

	fileTypes := make(map[string]int)
	var totalSize int64

	for _, doc := range docs {
		// Count by file extension
		if ext, ok := doc.Metadata["file_ext"]; ok {
			fileTypes[ext]++
		}

		// Sum file sizes
		if sizeStr, ok := doc.Metadata["file_size"]; ok {
			var size int64
			// Ignore parse errors - if invalid, just skip this file's size
			if _, err := fmt.Sscanf(sizeStr, "%d", &size); err == nil {
				totalSize += size
			}
		}
	}

	stats["file_types"] = fileTypes
	stats["total_size"] = totalSize

	return stats, nil
}

// generateDocID generates a unique document ID from file path
func generateDocID(filePath string) string {
	// Use absolute path for consistency
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}

	// Generate SHA256 hash of the absolute path
	hash := sha256.Sum256([]byte(absPath))
	return "file_" + hex.EncodeToString(hash[:16]) // Use first 16 bytes (32 hex chars)
}
