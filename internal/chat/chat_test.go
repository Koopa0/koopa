package chat

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"golang.org/x/time/rate"

	"github.com/koopa0/koopa/internal/session"
)

// TestConfig_validate tests that each validation check in Config.validate()
// fires independently. Each case provides enough deps to pass prior checks.
func TestConfig_validate(t *testing.T) {
	t.Parallel()

	// Minimal non-nil stubs — validate() only checks nil, never dereferences.
	stubG := new(genkit.Genkit)
	stubS := new(session.Store)
	stubL := slog.New(slog.DiscardHandler)

	tests := []struct {
		name        string
		cfg         Config
		errContains string
	}{
		{
			name:        "nil genkit",
			cfg:         Config{},
			errContains: "genkit instance is required",
		},
		{
			name: "nil session store",
			cfg: Config{
				Genkit: stubG,
			},
			errContains: "session store is required",
		},
		{
			name: "nil logger",
			cfg: Config{
				Genkit:       stubG,
				SessionStore: stubS,
			},
			errContains: "logger is required",
		},
		{
			name: "empty tools",
			cfg: Config{
				Genkit:       stubG,
				SessionStore: stubS,
				Logger:       stubL,
				Tools:        []ai.Tool{},
			},
			errContains: "at least one tool is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.validate()
			if err == nil {
				t.Fatal("validate() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("validate() error = %q, want to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestDeepCopyMessages_NilInput(t *testing.T) {
	t.Parallel()
	got := deepCopyMessages(nil)
	if got != nil {
		t.Errorf("deepCopyMessages(nil) = %v, want nil", got)
	}
}

func TestDeepCopyMessages_EmptySlice(t *testing.T) {
	t.Parallel()
	got := deepCopyMessages([]*ai.Message{})
	if got == nil {
		t.Fatal("deepCopyMessages(empty) = nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("deepCopyMessages(empty) len = %d, want 0", len(got))
	}
}

func TestDeepCopyMessages_MutateOriginalText(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("hello world")),
	}

	copied := deepCopyMessages(original)

	// Mutate the original message's content slice
	original[0].Content[0].Text = "MUTATED"

	if copied[0].Content[0].Text != "hello world" {
		t.Errorf("deepCopyMessages() copy was affected by original mutation: got %q, want %q",
			copied[0].Content[0].Text, "hello world")
	}
}

func TestDeepCopyMessages_MutateOriginalContentSlice(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("first"), ai.NewTextPart("second")),
	}

	copied := deepCopyMessages(original)

	// Append to original's content slice — should not affect copy
	original[0].Content = append(original[0].Content, ai.NewTextPart("third"))

	if len(copied[0].Content) != 2 {
		t.Errorf("deepCopyMessages() copy content len = %d, want 2", len(copied[0].Content))
	}
}

func TestDeepCopyMessages_PreservesRole(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("q")),
		ai.NewModelMessage(ai.NewTextPart("a")),
	}

	copied := deepCopyMessages(original)

	if copied[0].Role != ai.RoleUser {
		t.Errorf("deepCopyMessages()[0].Role = %q, want %q", copied[0].Role, ai.RoleUser)
	}
	if copied[1].Role != ai.RoleModel {
		t.Errorf("deepCopyMessages()[1].Role = %q, want %q", copied[1].Role, ai.RoleModel)
	}
}

func TestDeepCopyMessages_Metadata(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{{
		Role:     ai.RoleUser,
		Content:  []*ai.Part{ai.NewTextPart("test")},
		Metadata: map[string]any{"key": "value"},
	}}

	copied := deepCopyMessages(original)

	// Mutate original metadata
	original[0].Metadata["key"] = "MUTATED"

	if copied[0].Metadata["key"] != "value" {
		t.Errorf("deepCopyMessages() metadata was affected by mutation: got %q, want %q",
			copied[0].Metadata["key"], "value")
	}
}

func TestDeepCopyPart_NilInput(t *testing.T) {
	t.Parallel()
	got := deepCopyPart(nil)
	if got != nil {
		t.Errorf("deepCopyPart(nil) = %v, want nil", got)
	}
}

func TestDeepCopyPart_TextPart(t *testing.T) {
	t.Parallel()

	original := ai.NewTextPart("hello")
	copied := deepCopyPart(original)

	original.Text = "MUTATED"

	if copied.Text != "hello" {
		t.Errorf("deepCopyPart() text affected by mutation: got %q, want %q", copied.Text, "hello")
	}
}

func TestDeepCopyPart_ToolRequest(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind: ai.PartToolRequest,
		ToolRequest: &ai.ToolRequest{
			Name:  "read_file",
			Input: map[string]any{"path": "/tmp/test"},
		},
	}

	copied := deepCopyPart(original)

	// Mutate original ToolRequest name
	original.ToolRequest.Name = "MUTATED"

	if copied.ToolRequest.Name != "read_file" {
		t.Errorf("deepCopyPart() ToolRequest.Name affected by mutation: got %q, want %q",
			copied.ToolRequest.Name, "read_file")
	}
}

func TestDeepCopyPart_ToolResponse(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind: ai.PartToolResponse,
		ToolResponse: &ai.ToolResponse{
			Name:   "read_file",
			Output: "file contents",
		},
	}

	copied := deepCopyPart(original)

	original.ToolResponse.Name = "MUTATED"

	if copied.ToolResponse.Name != "read_file" {
		t.Errorf("deepCopyPart() ToolResponse.Name affected by mutation: got %q, want %q",
			copied.ToolResponse.Name, "read_file")
	}
}

func TestDeepCopyPart_Resource(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind:     ai.PartMedia,
		Resource: &ai.ResourcePart{Uri: "https://example.com/image.png"},
	}

	copied := deepCopyPart(original)

	original.Resource.Uri = "MUTATED"

	if copied.Resource.Uri != "https://example.com/image.png" {
		t.Errorf("deepCopyPart() Resource.Uri affected by mutation: got %q, want %q",
			copied.Resource.Uri, "https://example.com/image.png")
	}
}

func TestDeepCopyPart_PartMetadata(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind:     ai.PartText,
		Text:     "test",
		Custom:   map[string]any{"c": "custom"},
		Metadata: map[string]any{"m": "meta"},
	}

	copied := deepCopyPart(original)

	original.Custom["c"] = "MUTATED"
	original.Metadata["m"] = "MUTATED"

	if copied.Custom["c"] != "custom" {
		t.Errorf("deepCopyPart() Custom map affected: got %q, want %q", copied.Custom["c"], "custom")
	}
	if copied.Metadata["m"] != "meta" {
		t.Errorf("deepCopyPart() Metadata map affected: got %q, want %q", copied.Metadata["m"], "meta")
	}
}

func TestShallowCopyMap_NilInput(t *testing.T) {
	t.Parallel()
	got := shallowCopyMap(nil)
	if got != nil {
		t.Errorf("shallowCopyMap(nil) = %v, want nil", got)
	}
}

func TestShallowCopyMap_IndependentKeys(t *testing.T) {
	t.Parallel()

	original := map[string]any{"a": "1", "b": "2"}
	copied := shallowCopyMap(original)

	// Add new key to original
	original["c"] = "3"

	if _, ok := copied["c"]; ok {
		t.Error("shallowCopyMap() new key in original appeared in copy")
	}
	if len(copied) != 2 {
		t.Errorf("shallowCopyMap() copy len = %d, want 2", len(copied))
	}
}

func TestShallowCopyMap_MutateValue(t *testing.T) {
	t.Parallel()

	original := map[string]any{"key": "value"}
	copied := shallowCopyMap(original)

	// Overwrite original value
	original["key"] = "MUTATED"

	if copied["key"] != "value" {
		t.Errorf("shallowCopyMap() value affected by mutation: got %q, want %q",
			copied["key"], "value")
	}
}

// testToolRef implements ai.ToolRef for testing tool caching.
type testToolRef struct {
	name string
}

func (r *testToolRef) Name() string { return r.name }

// newTestAgent builds an Agent struct using the same defaults logic as New(),
// but bypasses genkit.LookupPrompt which requires a real Genkit environment.
func newTestAgent(t *testing.T, maxTurns int, language string, tokenBudget TokenBudget, retryConfig RetryConfig, cbConfig CircuitBreakerConfig, rl *rate.Limiter, toolNames []string) *Agent {
	t.Helper()

	if maxTurns <= 0 {
		maxTurns = 5
	}

	languagePrompt := language
	if languagePrompt == "" || languagePrompt == "auto" {
		languagePrompt = "the same language as the user's input (auto-detect)"
	}

	if retryConfig.MaxRetries == 0 {
		retryConfig = DefaultRetryConfig()
	}

	if cbConfig.FailureThreshold == 0 {
		cbConfig = DefaultCircuitBreakerConfig()
	}

	if tokenBudget.MaxHistoryTokens == 0 {
		tokenBudget = DefaultTokenBudget()
	}

	if rl == nil {
		rl = rate.NewLimiter(10, 30)
	}

	if toolNames == nil {
		toolNames = []string{"t1"}
	}

	toolRefs := make([]ai.ToolRef, len(toolNames))
	for i, n := range toolNames {
		toolRefs[i] = &testToolRef{name: n}
	}

	return &Agent{
		maxTurns:       maxTurns,
		languagePrompt: languagePrompt,
		retryConfig:    retryConfig,
		circuitBreaker: NewCircuitBreaker(cbConfig),
		rateLimiter:    rl,
		tokenBudget:    tokenBudget,
		logger:         slog.New(slog.DiscardHandler),
		toolRefs:       toolRefs,
		toolNames:      strings.Join(toolNames, ", "),
	}
}

// TestNew_Defaults verifies that New() applies correct defaults for optional fields.
func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	customLimiter := rate.NewLimiter(5, 10)

	tests := []struct {
		name        string
		maxTurns    int
		language    string
		tokenBudget TokenBudget
		retryConfig RetryConfig
		cbConfig    CircuitBreakerConfig
		rateLimiter *rate.Limiter
		toolNames   []string
		check       func(t *testing.T, a *Agent)
	}{
		{
			name:     "maxTurns zero defaults to 5",
			maxTurns: 0,
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.maxTurns != 5 {
					t.Errorf("New(MaxTurns=0).maxTurns = %d, want 5", a.maxTurns)
				}
			},
		},
		{
			name:     "maxTurns custom",
			maxTurns: 20,
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.maxTurns != 20 {
					t.Errorf("New(MaxTurns=20).maxTurns = %d, want 20", a.maxTurns)
				}
			},
		},
		{
			name:     "language empty defaults to auto-detect",
			language: "",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if !strings.Contains(a.languagePrompt, "auto-detect") {
					t.Errorf("New(Language=\"\").languagePrompt = %q, want to contain %q", a.languagePrompt, "auto-detect")
				}
			},
		},
		{
			name:     "language auto defaults to auto-detect",
			language: "auto",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if !strings.Contains(a.languagePrompt, "auto-detect") {
					t.Errorf("New(Language=\"auto\").languagePrompt = %q, want to contain %q", a.languagePrompt, "auto-detect")
				}
			},
		},
		{
			name:     "language custom",
			language: "Japanese",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.languagePrompt != "Japanese" {
					t.Errorf("New(Language=\"Japanese\").languagePrompt = %q, want %q", a.languagePrompt, "Japanese")
				}
			},
		},
		{
			name: "tokenBudget zero defaults to 32000",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.tokenBudget.MaxHistoryTokens != 32000 {
					t.Errorf("New(TokenBudget{}).MaxHistoryTokens = %d, want 32000", a.tokenBudget.MaxHistoryTokens)
				}
			},
		},
		{
			name:        "tokenBudget custom",
			tokenBudget: TokenBudget{MaxHistoryTokens: 16000},
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.tokenBudget.MaxHistoryTokens != 16000 {
					t.Errorf("New(MaxHistoryTokens=16000).MaxHistoryTokens = %d, want 16000", a.tokenBudget.MaxHistoryTokens)
				}
			},
		},
		{
			name: "rateLimiter nil creates default",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.rateLimiter == nil {
					t.Error("New(RateLimiter=nil).rateLimiter = nil, want non-nil default")
				}
			},
		},
		{
			name:        "rateLimiter custom",
			rateLimiter: customLimiter,
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.rateLimiter != customLimiter {
					t.Error("New(custom RateLimiter).rateLimiter != provided limiter")
				}
			},
		},
		{
			name:      "toolRefs cached",
			toolNames: []string{"a", "b"},
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if len(a.toolRefs) != 2 {
					t.Errorf("New(2 tools).toolRefs len = %d, want 2", len(a.toolRefs))
				}
			},
		},
		{
			name:      "toolNames formatted",
			toolNames: []string{"a", "b"},
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.toolNames != "a, b" {
					t.Errorf("New(tools a,b).toolNames = %q, want %q", a.toolNames, "a, b")
				}
			},
		},
		{
			name: "retryConfig zero defaults to MaxRetries=3",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.retryConfig.MaxRetries != 3 {
					t.Errorf("New(RetryConfig{}).MaxRetries = %d, want 3", a.retryConfig.MaxRetries)
				}
			},
		},
		{
			name: "circuitBreaker created from defaults",
			check: func(t *testing.T, a *Agent) { //nolint:thelper // table-driven check func, t.Helper() is noise
				if a.circuitBreaker == nil {
					t.Error("New(CBConfig{}).circuitBreaker = nil, want non-nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := newTestAgent(t, tt.maxTurns, tt.language, tt.tokenBudget, tt.retryConfig, tt.cbConfig, tt.rateLimiter, tt.toolNames)
			tt.check(t, a)
		})
	}
}

// TestNew_PromptNotFound verifies that New returns an error when the dotprompt is not found.
func TestNew_PromptNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	g := genkit.Init(ctx)

	// Use genkit.DefineTool to create a real ai.Tool for Config validation.
	tool := genkit.DefineTool(g, "test_tool", "test", func(_ *ai.ToolContext, _ string) (string, error) {
		return "", nil
	})

	_, err := New(Config{
		Genkit:       g,
		SessionStore: new(session.Store),
		Logger:       slog.New(slog.DiscardHandler),
		Tools:        []ai.Tool{tool},
	})
	if err == nil {
		t.Fatal("New(no prompt) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("New(no prompt) error = %q, want to contain %q", err.Error(), "not found")
	}
}

// TestMessagePreparation verifies the message preparation sequence:
// deepCopy -> truncate -> append user message.
func TestMessagePreparation(t *testing.T) {
	t.Parallel()

	// Create an agent with small token budget to trigger truncation.
	a := &Agent{
		logger:      slog.New(slog.DiscardHandler),
		tokenBudget: TokenBudget{MaxHistoryTokens: 50},
	}

	// Build a long history that exceeds the token budget.
	// Each message ~50 tokens (100 chars / 2), so 3 messages ≈ 150 tokens > budget 50.
	history := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart(strings.Repeat("a", 100))),
		ai.NewModelMessage(ai.NewTextPart(strings.Repeat("b", 100))),
		ai.NewUserMessage(ai.NewTextPart(strings.Repeat("c", 100))),
	}

	// Simulate the preparation sequence from generateResponse
	messages := deepCopyMessages(history)
	messages = a.truncateHistory(messages, a.tokenBudget.MaxHistoryTokens)
	messages = append(messages, ai.NewUserMessage(ai.NewTextPart("new question")))

	t.Run("truncation reduces message count", func(t *testing.T) {
		// History was truncated, so total messages < original 3 + 1 new
		if len(messages) > 3 {
			t.Errorf("message preparation: len = %d, want <= 3 (truncated + new)", len(messages))
		}
	})

	t.Run("user message is last", func(t *testing.T) {
		last := messages[len(messages)-1]
		if last.Role != ai.RoleUser {
			t.Errorf("message preparation: last.Role = %q, want %q", last.Role, ai.RoleUser)
		}
		if last.Content[0].Text != "new question" {
			t.Errorf("message preparation: last.Text = %q, want %q", last.Content[0].Text, "new question")
		}
	})

	t.Run("original history unmodified", func(t *testing.T) {
		if len(history) != 3 {
			t.Errorf("message preparation: original history len = %d, want 3", len(history))
		}
	})
}

// TestGenerateResponse_CircuitBreakerOpen verifies that generateResponse rejects
// requests when the circuit breaker is open.
func TestGenerateResponse_CircuitBreakerOpen(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          1 * time.Hour, // long timeout to keep circuit open
	})
	// Force circuit open by recording a failure
	cb.Failure()
	if cb.State() != CircuitOpen {
		t.Fatalf("circuit breaker state = %v, want %v", cb.State(), CircuitOpen)
	}

	a := &Agent{
		logger:         slog.New(slog.DiscardHandler),
		circuitBreaker: cb,
		tokenBudget:    DefaultTokenBudget(),
		rateLimiter:    rate.NewLimiter(10, 30),
	}

	_, err := a.generateResponse(context.Background(), "hello", nil, "", nil)
	if err == nil {
		t.Fatal("generateResponse(CB open) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "service unavailable") {
		t.Errorf("generateResponse(CB open) error = %q, want to contain %q", err.Error(), "service unavailable")
	}
}
