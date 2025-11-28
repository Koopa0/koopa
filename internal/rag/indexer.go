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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ignore "github.com/sabhiram/go-gitignore"

	"github.com/koopa0/koopa-cli/internal/knowledge"
)

// IndexerStore defines the interface for storage operations needed by Indexer.
// Following Go best practices: interfaces are defined by the consumer, not the provider
// (similar to io.Reader, http.RoundTripper, sql.Driver).
//
// This interface allows Indexer to depend on abstraction rather than concrete implementation,
// improving testability and flexibility.
type IndexerStore interface {
	// Add adds a document to the store
	Add(ctx context.Context, doc knowledge.Document) error

	// ListBySourceType lists documents by source type
	ListBySourceType(ctx context.Context, sourceType string, limit int32) ([]knowledge.Document, error)

	// Delete removes a document by ID
	Delete(ctx context.Context, docID string) error
}

// defaultSupportedExtensions are the default file types we can index
var defaultSupportedExtensions = map[string]bool{
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

// MaxFileSizeForEmbedding is the maximum file size that can be reliably embedded.
// text-embedding-004 has ~2048 token limit, which translates to approximately 8KB of text.
// Files larger than this will have their content truncated during embedding,
// causing retrieval failures for content beyond this limit.
const MaxFileSizeForEmbedding = 8 * 1024 // 8KB conservative limit for 2048 tokens

// DefaultListLimit is the default maximum number of documents returned by ListDocuments.
// This prevents unbounded queries that could cause memory exhaustion.
const DefaultListLimit = 1000

// Indexer handles local file indexing
type Indexer struct {
	store               IndexerStore    // Depends on interface for testability
	supportedExtensions map[string]bool // Configurable supported extensions
}

// NewIndexer creates a new file indexer
//
// Design: Accepts IndexerStore interface following "Accept interfaces, return structs"
// principle for better testability. knowledge.Store automatically satisfies this interface
// through duck typing.
//
// extensions: Optional list of supported file extensions (e.g. [".txt", ".md"]).
// If empty/nil, uses defaultSupportedExtensions.
func NewIndexer(store IndexerStore, extensions []string) *Indexer {
	extMap := make(map[string]bool)

	if len(extensions) > 0 {
		for _, ext := range extensions {
			extMap[strings.ToLower(ext)] = true
		}
	} else {
		// Use defaults - IMPORTANT: Copy the map to avoid data races
		// If we assign the reference directly, multiple Indexer instances
		// would share the same map, causing concurrent modification issues
		extMap = make(map[string]bool, len(defaultSupportedExtensions))
		for k, v := range defaultSupportedExtensions {
			// Normalize to lowercase for case-insensitive matching
			// This ensures consistency with custom extension handling (line 99)
			extMap[strings.ToLower(k)] = v
		}
	}

	return &Indexer{
		store:               store,
		supportedExtensions: extMap,
	}
}

// AddFile adds a single file to the knowledge store
func (idx *Indexer) AddFile(ctx context.Context, filePath string) error {
	// Get absolute path for consistency
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Open filesystem root at the file's parent directory
	// This prevents path traversal attacks using os.Root API (Go 1.24+)
	parentDir := filepath.Dir(absPath)
	fileName := filepath.Base(absPath)

	root, err := os.OpenRoot(parentDir)
	if err != nil {
		return fmt.Errorf("failed to open root directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	// Stat the file through the restricted root
	info, err := root.Stat(fileName)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, use AddDirectory instead")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(fileName))
	if !idx.supportedExtensions[ext] {
		return fmt.Errorf("unsupported file type: %s", ext)
	}

	// Check file size against embedding model limit
	// text-embedding-004 has ~2048 token limit; files larger than MaxFileSizeForEmbedding
	// will have content truncated during embedding, causing retrieval failures
	if info.Size() > MaxFileSizeForEmbedding {
		return fmt.Errorf("file %s (%d bytes) exceeds embedding limit (%d bytes); consider splitting into smaller files",
			fileName, info.Size(), MaxFileSizeForEmbedding)
	}

	// Read file content through the restricted root
	// This is secure - os.Root prevents path traversal and symlink escapes
	content, err := root.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Generate document ID from absolute path
	docID := generateDocID(absPath)

	// Create knowledge document
	doc := knowledge.Document{
		ID:      docID,
		Content: string(content),
		Metadata: map[string]string{
			"source_type": knowledge.SourceTypeFile,
			"file_path":   absPath,
			"file_name":   fileName,
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
//
//nolint:gocognit,gocyclo // TODO: Extract security checks to separate directoryWalker type for auditability
func (idx *Indexer) AddDirectory(ctx context.Context, dirPath string) (*IndexResult, error) {
	startTime := time.Now()
	result := &IndexResult{}

	// Get absolute path for the directory
	absDirPath, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute directory path: %w", err)
	}

	// Open filesystem root for the directory
	// This prevents path traversal attacks using os.Root API (Go 1.24+)
	root, err := os.OpenRoot(absDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	// SECURITY: Get root directory's device ID to detect hardlink attacks
	// Hardlinks can bypass symlink checks and allow access to files outside the root.
	// While os.OpenRoot protects path traversal, it doesn't prevent hardlinks
	// that point to files on the same filesystem but outside the root directory.
	// Note: This is Unix-specific; on other platforms, getDeviceID returns false.
	var rootDeviceID int64
	var hasRootDeviceID bool
	rootStat, err := os.Stat(absDirPath)
	if err == nil {
		rootDeviceID, hasRootDeviceID = getDeviceID(rootStat)
	}

	// Load .gitignore file if it exists
	var gitIgnore *ignore.GitIgnore
	gitignorePath := filepath.Join(absDirPath, ".gitignore")
	if _, statErr := os.Stat(gitignorePath); statErr == nil {
		var compileErr error
		gitIgnore, compileErr = ignore.CompileIgnoreFile(gitignorePath)
		if compileErr != nil {
			// If .gitignore is malformed, log and continue without it
			// Don't fail the entire operation
			gitIgnore = nil
		}
	}

	// Walk the directory tree using filepath.WalkDir (Go 1.16+)
	// SECURITY: WalkDir does NOT follow symlinks automatically, unlike Walk.
	// This is critical for preventing symlink traversal attacks that could
	// escape the os.OpenRoot security boundary.
	//nolint:nilerr // WalkDir callback returns nil to continue walking despite per-file errors
	if err = filepath.WalkDir(absDirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.FilesFailed++
			return nil // Continue walking even if one file fails
		}

		// SECURITY: Skip symlinks to prevent traversal outside os.OpenRoot boundary
		// WalkDir's d.Type() returns the symlink's own type, not the target's type.
		// This is the key difference from Walk which follows symlinks automatically.
		if d.Type()&fs.ModeSymlink != 0 {
			slog.Debug("skipping symlink during directory indexing",
				"path", path,
				"security_event", "symlink_skipped")
			if d.IsDir() {
				return filepath.SkipDir // Skip symlink directory tree
			}
			result.FilesSkipped++
			return nil // Skip symlink file
		}

		// Get relative path from the root directory (for gitignore matching)
		relPath, err := filepath.Rel(absDirPath, path)
		if err != nil {
			result.FilesFailed++
			return nil // Continue walking despite individual file errors
		}

		// Check if should be ignored by .gitignore (for both files and directories)
		if gitIgnore != nil && gitIgnore.MatchesPath(relPath) {
			if d.IsDir() {
				return filepath.SkipDir // Skip entire directory tree
			}
			result.FilesSkipped++
			return nil
		}

		// Skip directories (that are not ignored)
		if d.IsDir() {
			return nil
		}

		// Get file info for size check
		info, err := d.Info()
		if err != nil {
			slog.Warn("failed to get file info",
				"path", path,
				"error", err)
			result.FilesFailed++
			return nil // Continue walking
		}

		// SECURITY: Detect potential hardlink attacks (Unix-specific)
		// Hardlinks with nlink > 1 pointing to files outside the root could be attack vectors.
		// We check: 1) device ID mismatch, 2) suspicious hardlink count for sensitive extensions
		// Note: On non-Unix platforms, these checks are skipped (getDeviceID returns false)
		if fileDeviceID, ok := getDeviceID(info); ok && hasRootDeviceID {
			// Skip files from different devices (shouldn't happen, but defense in depth)
			if fileDeviceID != rootDeviceID {
				slog.Warn("skipping file from different device",
					"path", path,
					"root_device", rootDeviceID,
					"file_device", fileDeviceID,
					"security_event", "cross_device_skipped")
				result.FilesSkipped++
				return nil
			}
		}

		// Log hardlinks as potential security concern (nlink > 1 means multiple names)
		// Note: We don't block hardlinks entirely as they have legitimate uses,
		// but we log them for security monitoring.
		if nlink, ok := getHardlinkCount(info); ok && nlink > 1 {
			slog.Debug("indexing file with multiple hardlinks",
				"path", path,
				"nlink", nlink,
				"security_event", "hardlink_detected")
		}

		// Check if file type is supported
		ext := strings.ToLower(filepath.Ext(path))
		if !idx.supportedExtensions[ext] {
			result.FilesSkipped++
			return nil
		}

		// Check file size against embedding model limit
		if info.Size() > MaxFileSizeForEmbedding {
			result.FilesSkipped++ // Skip files too large for embedding
			return nil
		}

		// Read file through the secure root (prevents path traversal)
		content, err := root.ReadFile(relPath)
		if err != nil {
			result.FilesFailed++
			return nil // Continue walking despite individual file errors
		}

		// SECURITY: Defense in depth - verify content size after read (TOCTOU protection)
		if int64(len(content)) > MaxFileSizeForEmbedding {
			result.FilesSkipped++
			return nil
		}

		// Generate document ID
		docID := generateDocID(path)

		// Create knowledge document
		doc := knowledge.Document{
			ID:      docID,
			Content: string(content),
			Metadata: map[string]string{
				"source_type": knowledge.SourceTypeFile,
				"file_path":   path,
				"file_name":   filepath.Base(path),
				"file_ext":    ext,
				"file_size":   fmt.Sprintf("%d", info.Size()),
				"indexed_at":  time.Now().Format(time.RFC3339),
			},
			CreateAt: time.Now(),
		}

		// Add to knowledge store
		if err := idx.store.Add(ctx, doc); err != nil {
			result.FilesFailed++
			return nil // Continue walking despite individual file errors
		}

		result.FilesAdded++
		result.TotalSize += info.Size()
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", absDirPath, err)
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// ListDocuments returns all indexed documents
func (idx *Indexer) ListDocuments(ctx context.Context) ([]knowledge.Document, error) {
	// Use ListBySourceType to get all file documents without needing embeddings
	docs, err := idx.store.ListBySourceType(ctx, knowledge.SourceTypeFile, DefaultListLimit)
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
		// Graceful degradation: return empty stats on error (e.g., DB unavailable)
		//nolint:nilerr // Intentional graceful degradation - return empty stats on error
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
