// Package rag constants.go defines shared constants, types, and configuration for RAG operations.
//
// Contents:
//   - Source type constants (SourceTypeConversation, SourceTypeFile, SourceTypeSystem)
//   - Table schema constants for documents table
//   - NewDocStoreConfig factory for consistent DocStore configuration
package rag

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/plugins/postgresql"
)

// Source type constants for knowledge documents.
// These define the categories of knowledge stored in the system.
const (
	// SourceTypeConversation represents chat message history.
	SourceTypeConversation = "conversation"

	// SourceTypeFile represents indexed file content.
	SourceTypeFile = "file"

	// SourceTypeSystem represents system knowledge (best practices, coding standards).
	SourceTypeSystem = "system"
)

// Table schema constants for Genkit PostgreSQL plugin.
// These match the documents table in db/migrations.
const (
	DocumentsTableName    = "documents"
	DocumentsSchemaName   = "public"
	DocumentsIDColumn     = "id"
	DocumentsContentCol   = "content"
	DocumentsEmbeddingCol = "embedding"
	DocumentsMetadataCol  = "metadata"
)

// NewDocStoreConfig creates a postgresql.Config for the documents table.
// This factory ensures consistent configuration across production and tests.
func NewDocStoreConfig(embedder ai.Embedder) *postgresql.Config {
	return &postgresql.Config{
		TableName:          DocumentsTableName,
		SchemaName:         DocumentsSchemaName,
		IDColumn:           DocumentsIDColumn,
		ContentColumn:      DocumentsContentCol,
		EmbeddingColumn:    DocumentsEmbeddingCol,
		MetadataJSONColumn: DocumentsMetadataCol,
		MetadataColumns:    []string{"source_type"}, // For filtering by type
		Embedder:           embedder,
	}
}
