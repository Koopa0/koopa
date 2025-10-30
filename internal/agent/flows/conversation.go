package flows

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/agent/tools"
)

// ChatInput represents input for chat flow
type ChatInput struct {
	Message string        `json:"message"`           // User message
	History []*ai.Message `json:"history,omitempty"` // Conversation history
}

// defineConversationFlows defines conversation-related flows
func defineConversationFlows(g *genkit.Genkit, modelRef ai.ModelRef, systemPrompt string) {
	// Streaming chat flow - provides real-time conversational experience
	genkit.DefineStreamingFlow(g, "chat",
		func(ctx context.Context, input ChatInput, callback core.StreamCallback[string]) (string, error) {
			// Build messages: system + history + new user message
			messages := []*ai.Message{ai.NewUserMessage(ai.NewTextPart(input.Message))}
			if len(input.History) > 0 {
				messages = append(input.History, messages...)
			}

			// Get all registered tools (always use tools)
			toolNames := tools.GetToolNames()
			toolRefs := make([]ai.ToolRef, 0, len(toolNames))
			for _, name := range toolNames {
				if tool := genkit.LookupTool(g, name); tool != nil {
					toolRefs = append(toolRefs, tool)
				}
			}

			// Build generate options (always includes tools)
			opts := []ai.GenerateOption{
				ai.WithModel(modelRef),
				ai.WithSystem(systemPrompt),
				ai.WithMessages(messages...),
				ai.WithStreaming(func(ctx context.Context, chunk *ai.ModelResponseChunk) error {
					if callback != nil {
						if err := callback(ctx, chunk.Text()); err != nil {
							return err
						}
					}
					return nil
				}),
				ai.WithTools(toolRefs...),
			}

			// Generate response with streaming
			response, err := genkit.Generate(ctx, g, opts...)
			if err != nil {
				return "", err
			}

			return response.Text(), nil
		})
}
