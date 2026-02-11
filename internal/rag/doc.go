// Package rag implements Retrieval-Augmented Generation (RAG) for Koopa.
//
// The rag package provides document indexing and knowledge base integration for LLM applications.
// It uses Firebase Genkit's PostgreSQL plugin for vector storage and retrieval.
//
// # Overview
//
// RAG enhances LLM responses by augmenting prompts with relevant context from a knowledge base.
// The rag package manages:
//
//   - DocStore configuration for vector storage
//   - Integration with Genkit's PostgreSQL DocStore
//
// # Architecture
//
//	Genkit PostgreSQL DocStore
//	     |
//	     +-- Vector embedding (via AI Embedder)
//	     +-- Vector storage (PostgreSQL + pgvector)
//	     |
//	     v
//	Genkit Retriever (ai.Retriever interface)
//	     |
//	     +-- source_type filtering (conversation, file, system)
//	     +-- Semantic search
//	     |
//	     v
//	LLM (with augmented context)
//
// # Key Components
//
// NewDocStoreConfig: Creates configuration for the Genkit PostgreSQL DocStore.
//
// DeleteByIDs: Removes documents by ID for UPSERT emulation.
//
// # Source Types
//
// Documents are categorized by source_type:
//
//   - SourceTypeConversation: Chat message history
//   - SourceTypeFile: Indexed file content
//   - SourceTypeSystem: Built-in system knowledge
//
// # Thread Safety
//
// DocStore handles concurrent operations safely.
package rag
