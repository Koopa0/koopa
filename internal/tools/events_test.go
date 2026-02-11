package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/firebase/genkit/go/ai"
)

// mockEmitterForEvents is a test implementation of Emitter.
type mockEmitterForEvents struct {
	startCalls    []string
	completeCalls []string
	errorCalls    []string
}

func (m *mockEmitterForEvents) OnToolStart(name string) {
	m.startCalls = append(m.startCalls, name)
}

func (m *mockEmitterForEvents) OnToolComplete(name string) {
	m.completeCalls = append(m.completeCalls, name)
}

func (m *mockEmitterForEvents) OnToolError(name string) {
	m.errorCalls = append(m.errorCalls, name)
}

// Verify mockEmitterForEvents implements Emitter.
var _ Emitter = (*mockEmitterForEvents)(nil)

func TestWithEvents_Success(t *testing.T) {
	emitter := &mockEmitterForEvents{}
	ctx := ContextWithEmitter(context.Background(), emitter)

	// Create a mock tool handler that returns success
	handler := func(_ *ai.ToolContext, input string) (string, error) {
		return "result: " + input, nil
	}

	// Wrap the handler
	wrapped := WithEvents("test_tool", handler)

	// Execute
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := wrapped(toolCtx, "input")

	// Verify results
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "result: input" {
		t.Errorf("result = %v, want 'result: input'", result)
	}

	// Verify events
	if len(emitter.startCalls) != 1 || emitter.startCalls[0] != "test_tool" {
		t.Errorf("startCalls = %v, want [test_tool]", emitter.startCalls)
	}
	if len(emitter.completeCalls) != 1 || emitter.completeCalls[0] != "test_tool" {
		t.Errorf("completeCalls = %v, want [test_tool]", emitter.completeCalls)
	}
	if len(emitter.errorCalls) != 0 {
		t.Errorf("errorCalls = %v, want []", emitter.errorCalls)
	}
}

func TestWithEvents_Error(t *testing.T) {
	emitter := &mockEmitterForEvents{}
	ctx := ContextWithEmitter(context.Background(), emitter)

	testErr := errors.New("test error")

	// Create a mock tool handler that returns an error
	handler := func(_ *ai.ToolContext, _ string) (string, error) {
		return "", testErr
	}

	// Wrap the handler
	wrapped := WithEvents("failing_tool", handler)

	// Execute
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := wrapped(toolCtx, "input")

	// Verify results
	if !errors.Is(err, testErr) {
		t.Errorf("error = %v, want %v", err, testErr)
	}
	if result != "" {
		t.Errorf("result = %v, want empty string", result)
	}

	// Verify events
	if len(emitter.startCalls) != 1 || emitter.startCalls[0] != "failing_tool" {
		t.Errorf("startCalls = %v, want [failing_tool]", emitter.startCalls)
	}
	if len(emitter.completeCalls) != 0 {
		t.Errorf("completeCalls = %v, want []", emitter.completeCalls)
	}
	if len(emitter.errorCalls) != 1 || emitter.errorCalls[0] != "failing_tool" {
		t.Errorf("errorCalls = %v, want [failing_tool]", emitter.errorCalls)
	}
}

func TestWithEvents_NoEmitter(t *testing.T) {
	// Test graceful degradation when no emitter is set
	ctx := context.Background() // No emitter in context

	callCount := 0
	handler := func(_ *ai.ToolContext, input string) (string, error) {
		callCount++
		return input, nil
	}

	wrapped := WithEvents("tool", handler)

	// Execute
	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := wrapped(toolCtx, "test")

	// Verify handler was called and no panic
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "test" {
		t.Errorf("result = %v, want 'test'", result)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}
}

func TestWithEvents_TypedResults(t *testing.T) {
	emitter := &mockEmitterForEvents{}
	ctx := ContextWithEmitter(context.Background(), emitter)

	// Test with Result type to match actual tool usage
	handler := func(_ *ai.ToolContext, _ struct{}) (Result, error) {
		return Result{Status: StatusSuccess, Data: "done"}, nil
	}

	wrapped := WithEvents("typed_tool", handler)

	toolCtx := &ai.ToolContext{Context: ctx}
	result, err := wrapped(toolCtx, struct{}{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Errorf("result.Status = %v, want %v", result.Status, StatusSuccess)
	}
	if len(emitter.completeCalls) != 1 {
		t.Errorf("completeCalls = %v, want 1 call", emitter.completeCalls)
	}
}

func TestWithEvents_MultipleToolCalls(t *testing.T) {
	emitter := &mockEmitterForEvents{}
	ctx := ContextWithEmitter(context.Background(), emitter)

	handler := func(_ *ai.ToolContext, input int) (int, error) {
		return input * 2, nil
	}

	wrapped := WithEvents("multi_tool", handler)

	toolCtx := &ai.ToolContext{Context: ctx}

	// Call multiple times
	for i := 1; i <= 3; i++ {
		result, err := wrapped(toolCtx, i)
		if err != nil {
			t.Errorf("call %d: unexpected error: %v", i, err)
		}
		if result != i*2 {
			t.Errorf("call %d: result = %d, want %d", i, result, i*2)
		}
	}

	// Verify all events recorded
	if len(emitter.startCalls) != 3 {
		t.Errorf("startCalls count = %d, want 3", len(emitter.startCalls))
	}
	if len(emitter.completeCalls) != 3 {
		t.Errorf("completeCalls count = %d, want 3", len(emitter.completeCalls))
	}
}

func TestWithEvents_EmptyContext(t *testing.T) {
	// Test behavior when ToolContext has empty (non-nil) Context
	// Note: nil Context would panic in EmitterFromContext
	handler := func(_ *ai.ToolContext, _ string) (string, error) {
		return "ok", nil
	}

	wrapped := WithEvents("empty_ctx_tool", handler)

	// Create ToolContext with empty (non-nil) Context
	toolCtx := &ai.ToolContext{Context: context.Background()}

	result, err := wrapped(toolCtx, "input")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %v, want 'ok'", result)
	}
}
