package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/koopa0/koopa/internal/knowledge"
	"github.com/koopa0/koopa/internal/retriever"
	"github.com/spf13/cobra"
)

// NewAskCmd creates the ask command (factory pattern)
func NewAskCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "ask [question]",
		Short: i18n.T("ask.description"),
		Args:  cobra.MinimumNArgs(1),
		Annotations: map[string]string{
			"requiresAPIKey": "true", // Declarative: this command requires API Key
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAsk(cmd.Context(), cfg, args)
		},
	}
}

func runAsk(ctx context.Context, cfg *config.Config, args []string) error {
	// API Key already checked in PersistentPreRunE

	// Step 1: Initialize Genkit
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)

	// Step 2: Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)

	// Step 3: Initialize knowledge store
	knowledgeStore, err := knowledge.New(cfg.VectorPath, "koopa-knowledge", embedder, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize knowledge store: %w", err)
	}
	defer knowledgeStore.Close()

	// Step 4: Create retriever (without session filtering for ask command)
	ret := retriever.New(knowledgeStore)
	retrieverRef := ret.DefineConversation(g, "conversation")

	// Step 5: Create Agent with RAG support
	ag, err := agent.New(ctx, cfg, g, retrieverRef)
	if err != nil {
		return fmt.Errorf(i18n.T("error.agent"), err)
	}

	// Merge all arguments as question
	question := strings.Join(args, " ")
	if question == "" {
		return errors.New(i18n.T("error.question.empty"))
	}

	// Ask AI (always uses tools and RAG)
	answer, err := ag.Ask(ctx, question)
	if err != nil {
		return fmt.Errorf(i18n.T("error.generate"), err)
	}

	// Display response
	fmt.Println(answer)

	return nil
}
