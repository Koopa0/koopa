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
//   - System knowledge indexing (IndexSystemKnowledge function)
//   - Integration with Genkit's PostgreSQL DocStore
//
// # Architecture
//
//	System Knowledge Docs
//	     |
//	     v
//	IndexSystemKnowledge()
//	     |
//	     v
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
// IndexSystemKnowledge: Package-level function that indexes built-in knowledge:
//   - Go best practices and coding standards
//   - Agent capabilities and tool usage
//   - Architecture principles
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
// IndexSystemKnowledge is called once at startup.
package rag
