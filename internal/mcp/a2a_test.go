package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// Unit tests for the A2A coordination tools (a2a.go) — DB-free dimensions.
//
// The file_report and acknowledge_directive pre-DB validation paths are
// covered in handler_test.go (TestFileReport_Validation,
// TestAcknowledgeDirective_Validation); the propose_directive title contract
// is covered in commitment_test.go (TestExtractTitleFromFirstTextPart). This
// file fills the one remaining CI-visible gap: task_detail rejects a malformed
// task_id at the parsing boundary, before any store call, so a nil-store
// newTestServer() is sufficient and the check runs in the default
// `go test ./...` lane (the integration suite also pins it under build tag,
// but that lane does not run in first-signal CI).
//
// DB-backed behavior (the directive→ack→report chain, conflicts, actor
// enforcement, not-found, state edges) lives in a2a_integration_test.go.

func TestTaskDetail_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   TaskDetailInput
		wantErr string
	}{
		{name: "empty task_id", input: TaskDetailInput{}, wantErr: "invalid task_id"},
		{name: "malformed task_id", input: TaskDetailInput{TaskID: "not-a-uuid"}, wantErr: "invalid task_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.taskDetail, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestParseA2APartsAccepts pins the four canonical a2a Part shapes that
// callers may send (text / raw / data / url) and the optional sibling
// fields that may accompany them. This is the consumer-facing contract;
// regressing it would break every cowork agent that files an artifact.
func TestParseA2APartsAccepts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "text", raw: `{"text":"summary prose"}`},
		{name: "raw", raw: `{"raw":"aGVsbG8="}`},
		{name: "data object", raw: `{"data":{"signal":"weakness","concept":"binary-search"}}`},
		{name: "data array", raw: `{"data":[1,2,3]}`},
		{name: "url with mediaType", raw: `{"url":"https://example.com/x.png","mediaType":"image/png"}`},
		{name: "text with filename", raw: `{"text":"chapter 3","filename":"chapter-03.md"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := parseA2AParts([]json.RawMessage{json.RawMessage(tt.raw)})
			if err != nil {
				t.Fatalf("parseA2AParts(%q) error = %v, want nil", tt.raw, err)
			}
			if len(parts) != 1 {
				t.Fatalf("parseA2AParts(%q) len = %d, want 1", tt.raw, len(parts))
			}
		})
	}
}

// TestParseA2APartsRejectsAndHints verifies the rejection paths and that
// every error carries the "valid keys" hint. Without the hint, the
// upstream a2a-go error ("unknown part content type: [type concept ...]")
// lists the caller's bad keys, not the allowed ones — the exact UX bug
// HERMES F-15 (2026-05-23) called out.
func TestParseA2APartsRejectsAndHints(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "no recognized key", raw: `{"type":"observation","concept":"x","signal":"weakness"}`},
		{name: "empty object", raw: `{}`},
		{name: "multiple content keys", raw: `{"text":"a","data":{"x":1}}`},
		{name: "not an object", raw: `"just a string"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseA2AParts([]json.RawMessage{json.RawMessage(tt.raw)})
			if err == nil {
				t.Fatalf("parseA2AParts(%q) error = nil, want non-nil", tt.raw)
			}
			if !strings.Contains(err.Error(), "valid keys: text, raw, data, url") {
				t.Errorf("parseA2AParts(%q) error = %q, want hint mentioning valid keys", tt.raw, err.Error())
			}
		})
	}
}

// TestParseA2APartsSummaryFootgun documents the silent-storage gotcha
// HERMES F-15 catalogued: a2a-go's Part.UnmarshalJSON dispatches by the
// presence of text/raw/data/url keys — `type` and other unknown keys
// are dropped without warning. A caller who sends
// {"type":"summary","text":"..."} thinks they wrote a typed Summary
// part; the server silently stores plain Text. We accept this rather
// than rejecting (D1 verdict 2026-05-23: documented-and-leave; a2a is
// an external protocol and rejecting its allowed extra keys risks
// interop). The test exists to make the behavior visible: if a future
// change starts rejecting unknown keys, this test fails and forces a
// conscious revisit of the policy.
func TestParseA2APartsSummaryFootgun(t *testing.T) {
	raw := `{"type":"summary","text":"the summary text"}`
	parts, err := parseA2AParts([]json.RawMessage{json.RawMessage(raw)})
	if err != nil {
		t.Fatalf("parseA2AParts(%q) error = %v, want nil (silent-storage footgun is accepted behavior)", raw, err)
	}
	if len(parts) != 1 {
		t.Fatalf("parseA2AParts(%q) len = %d, want 1", raw, len(parts))
	}
	if got := parts[0].Text(); got != "the summary text" {
		t.Errorf("parseA2AParts(%q) part stored as Text = %q, want %q (confirms `type` was silently dropped)", raw, got, "the summary text")
	}
}
