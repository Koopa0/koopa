package rag

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"google.golang.org/genai"
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

// VectorDimension is the vector dimension used by the pgvector schema.
// Must match the documents table migration: embedding vector(768).
// gemini-embedding-001 produces 3072 dimensions by default;
// we truncate to 768 via OutputDimensionality in EmbedderOptions.
const VectorDimension int32 = 768

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
// EmbedderOptions sets OutputDimensionality to match the pgvector schema.
func NewDocStoreConfig(embedder ai.Embedder) *postgresql.Config {
	dim := VectorDimension
	return &postgresql.Config{
		TableName:          DocumentsTableName,
		SchemaName:         DocumentsSchemaName,
		IDColumn:           DocumentsIDColumn,
		ContentColumn:      DocumentsContentCol,
		EmbeddingColumn:    DocumentsEmbeddingCol,
		MetadataJSONColumn: DocumentsMetadataCol,
		MetadataColumns:    []string{"source_type", "owner_id"}, // For filtering by type and owner
		Embedder:           embedder,
		EmbedderOptions:    &genai.EmbedContentConfig{OutputDimensionality: &dim},
	}
}
