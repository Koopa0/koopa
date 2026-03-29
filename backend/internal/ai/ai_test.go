package ai

import (
	"encoding/json"
	"testing"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/google/go-cmp/cmp"
)

// ---------------------------------------------------------------------------
// CheckFinishReason — every FinishReason enum value
// ---------------------------------------------------------------------------

func TestCheckFinishReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		resp    *genkitai.ModelResponse
		wantErr bool
		wantMsg string
	}{
		{name: "nil response is safe", resp: nil, wantErr: false},
		{name: "stop is safe", resp: &genkitai.ModelResponse{FinishReason: genkitai.FinishReasonStop}, wantErr: false},
		{name: "length is safe (by design)", resp: &genkitai.ModelResponse{FinishReason: genkitai.FinishReasonLength}, wantErr: false},
		{
			name:    "blocked returns ErrContentBlocked",
			resp:    &genkitai.ModelResponse{FinishReason: genkitai.FinishReasonBlocked, FinishMessage: "safety filter triggered"},
			wantErr: true,
			wantMsg: "content blocked",
		},
		{
			name:    "other returns ErrContentBlocked",
			resp:    &genkitai.ModelResponse{FinishReason: genkitai.FinishReasonOther, FinishMessage: "unexpected"},
			wantErr: true,
			wantMsg: "unexpected finish reason",
		},
		{name: "empty finish reason is safe", resp: &genkitai.ModelResponse{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckFinishReason(tt.resp)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("CheckFinishReason() = nil, want error")
				}
				if tt.wantMsg != "" && !contains(err.Error(), tt.wantMsg) {
					t.Errorf("CheckFinishReason() error = %q, want to contain %q", err, tt.wantMsg)
				}
			} else if err != nil {
				t.Errorf("CheckFinishReason() unexpected error: %v", err)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Registry — flow lookup
// ---------------------------------------------------------------------------

func TestRegistry(t *testing.T) {
	t.Parallel()

	flow1 := &mockFlow{name: "content-review", output: map[string]string{"status": "ok"}}
	flow2 := &mockFlow{name: "digest-generate", output: map[string]string{"status": "done"}}

	r := NewRegistry(flow1, flow2)

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		got := r.Flow("content-review")
		if got == nil {
			t.Fatal("Registry.Flow(\"content-review\") = nil")
		}
		if got.Name() != "content-review" {
			t.Errorf("Flow.Name() = %q, want %q", got.Name(), "content-review")
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		got := r.Flow("nonexistent")
		if got != nil {
			t.Errorf("Registry.Flow(\"nonexistent\") = %v, want nil", got)
		}
	})

	t.Run("empty registry", func(t *testing.T) {
		t.Parallel()
		empty := NewRegistry()
		if got := empty.Flow("anything"); got != nil {
			t.Errorf("empty Registry.Flow() = %v, want nil", got)
		}
	})
}

// ---------------------------------------------------------------------------
// mockFlow — Run returns valid JSON
// ---------------------------------------------------------------------------

func TestMockFlowRun(t *testing.T) {
	t.Parallel()

	m := &mockFlow{name: "test", output: map[string]int{"count": 42}}
	got, err := m.Run(t.Context(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("mockFlow.Run() error: %v", err)
	}

	var parsed map[string]int
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if diff := cmp.Diff(map[string]int{"count": 42}, parsed); diff != "" {
		t.Errorf("mockFlow.Run() mismatch (-want +got):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// Interface contract
// ---------------------------------------------------------------------------

var _ Flow = (*mockFlow)(nil)

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkCheckFinishReason(b *testing.B) {
	resp := &genkitai.ModelResponse{FinishReason: genkitai.FinishReasonStop}
	b.ReportAllocs()
	for b.Loop() {
		_ = CheckFinishReason(resp)
	}
}

func BenchmarkRegistryFlow(b *testing.B) {
	r := NewRegistry(
		&mockFlow{name: "a"}, &mockFlow{name: "b"}, &mockFlow{name: "c"},
		&mockFlow{name: "d"}, &mockFlow{name: "e"}, &mockFlow{name: "f"},
	)
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Flow("d")
	}
}
