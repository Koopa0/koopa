package hypothesis

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// decodeErrorResponse reads the canonical {"error":{code,message}} envelope.
func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) api.ErrorBody {
	t.Helper()
	var eb api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return eb
}

// newVerifyRequest constructs a POST /verify request with the given body
// and path UUID. body may be nil (no body), a byte slice (raw JSON), or
// any marshaled value.
func newVerifyRequest(t *testing.T, id string, body any) *http.Request {
	t.Helper()
	var buf *bytes.Buffer
	switch v := body.(type) {
	case nil:
		buf = bytes.NewBuffer(nil)
	case []byte:
		buf = bytes.NewBuffer(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshaling body: %v", err)
		}
		buf = bytes.NewBuffer(b)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hypotheses/"+id+"/verify", buf)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id)
	return req
}

// newVerifyHandler returns a Handler with a nil store. Safe only for
// tests whose request fails validation BEFORE a store call is reached.
func newVerifyHandler() *Handler {
	return NewHandler(nil, slog.New(slog.DiscardHandler))
}

// fixtureID is a stable UUID for test paths where the value does not matter.
const fixtureID = "11111111-1111-1111-1111-111111111111"

// ---------------------------------------------------------------------------
// Handler.Verify — validation table
//
// Covers the error-path scenarios from brief §9: no evidence → 422,
// malformed UUID → 400, oversize summary → 400. Happy-path roundtrips
// against UpdateResolution are exercised in the commit 25 integration
// test because they need a real database to validate the DB CHECK.
// ---------------------------------------------------------------------------

func TestVerify_NoEvidence_422(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body any
	}{
		{name: "empty body", body: nil},
		{name: "empty json object", body: map[string]any{}},
		{name: "all fields null", body: map[string]any{
			"resolved_by_attempt_id":     nil,
			"resolved_by_observation_id": nil,
			"resolution_summary":         nil,
		}},
		{name: "all fields blank strings", body: map[string]any{
			"resolved_by_attempt_id":     "",
			"resolved_by_observation_id": "",
			"resolution_summary":         "",
		}},
		{name: "whitespace-only summary", body: map[string]any{
			"resolution_summary": "   \t\n  ",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newVerifyHandler()
			req := newVerifyRequest(t, fixtureID, tt.body)
			w := httptest.NewRecorder()
			h.Verify(w, req)

			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("Verify(%q) status = %d, want %d (body: %s)",
					tt.name, w.Code, http.StatusUnprocessableEntity, w.Body.String())
			}
			eb := decodeErrorResponse(t, w)
			if diff := cmp.Diff("EVIDENCE_REQUIRED", eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVerify_MalformedAttemptUUID_400(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      map[string]any
		wantField string
	}{
		{
			name:      "malformed attempt id",
			body:      map[string]any{"resolved_by_attempt_id": "not-a-uuid"},
			wantField: "resolved_by_attempt_id",
		},
		{
			name:      "malformed observation id",
			body:      map[string]any{"resolved_by_observation_id": "also-not-a-uuid"},
			wantField: "resolved_by_observation_id",
		},
		{
			name: "malformed attempt id with valid summary",
			// UUID error must fire BEFORE falling back to summary-only path.
			body: map[string]any{
				"resolved_by_attempt_id": "garbage",
				"resolution_summary":     "solved cleanly",
			},
			wantField: "resolved_by_attempt_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newVerifyHandler()
			req := newVerifyRequest(t, fixtureID, tt.body)
			w := httptest.NewRecorder()
			h.Verify(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("Verify(%q) status = %d, want %d (body: %s)",
					tt.name, w.Code, http.StatusBadRequest, w.Body.String())
			}
			eb := decodeErrorResponse(t, w)
			if diff := cmp.Diff("BAD_REQUEST", eb.Error.Code); diff != "" {
				t.Errorf("error code mismatch (-want +got):\n%s", diff)
			}
			if !strings.Contains(eb.Error.Message, tt.wantField) {
				t.Errorf("Verify(%q) message = %q, want to contain %q",
					tt.name, eb.Error.Message, tt.wantField)
			}
		})
	}
}

func TestVerify_OversizeSummary_400(t *testing.T) {
	t.Parallel()

	// MaxResolutionSummary is 2 KB; build a string that exceeds it by one byte.
	oversize := strings.Repeat("a", MaxResolutionSummary+1)

	h := newVerifyHandler()
	req := newVerifyRequest(t, fixtureID, map[string]any{"resolution_summary": oversize})
	w := httptest.NewRecorder()
	h.Verify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Verify(oversize) status = %d, want %d (body: %s)",
			w.Code, http.StatusBadRequest, w.Body.String())
	}
	eb := decodeErrorResponse(t, w)
	if diff := cmp.Diff("BAD_REQUEST", eb.Error.Code); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}
	if !strings.Contains(eb.Error.Message, "resolution_summary") {
		t.Errorf("Verify(oversize) message = %q, want to contain %q",
			eb.Error.Message, "resolution_summary")
	}
}

func TestVerify_ControlCharSummary_400(t *testing.T) {
	t.Parallel()

	// Null byte in the middle of an otherwise valid summary must be
	// rejected at the validator layer (not quietly stripped by the DB).
	// See validate_test.go::TestValidateResolveInput_ControlChars for
	// the full character-class matrix; this test covers the wire
	// envelope the handler is expected to produce.
	body := map[string]any{"resolution_summary": "solved cleanly\x00"}
	h := newVerifyHandler()
	req := newVerifyRequest(t, fixtureID, body)
	w := httptest.NewRecorder()
	h.Verify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Verify(control char) status = %d, want %d (body: %s)",
			w.Code, http.StatusBadRequest, w.Body.String())
	}
	eb := decodeErrorResponse(t, w)
	if diff := cmp.Diff("BAD_REQUEST", eb.Error.Code); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}
	if !strings.Contains(eb.Error.Message, "control characters") {
		t.Errorf("Verify(control char) message = %q, want to contain %q",
			eb.Error.Message, "control characters")
	}
}

func TestVerify_MalformedPathID_400(t *testing.T) {
	t.Parallel()

	h := newVerifyHandler()
	req := newVerifyRequest(t, "not-a-uuid", map[string]any{"resolution_summary": "ok"})
	w := httptest.NewRecorder()
	h.Verify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Verify(bad path id) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	eb := decodeErrorResponse(t, w)
	if diff := cmp.Diff("BAD_REQUEST", eb.Error.Code); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// parseResolveRequest — happy-path parsing
//
// Covers the HappyPath_AttemptOnly and HappyPath_SummaryOnly cases from
// the brief. We exercise parseResolveRequest directly (rather than the
// full Verify handler) because the 200 response requires a UpdateResolution
// DB roundtrip, which belongs in the commit 25 integration test. The
// parser is the part of the 200 path that needs unit coverage: it must
// emit the right ResolveParams so the integration test sees the right
// SQL, and an integration test cannot distinguish "parser produced wrong
// params" from "DB rejected correct params."
// ---------------------------------------------------------------------------

func TestParseResolveRequest_HappyPath_AttemptOnly(t *testing.T) {
	t.Parallel()

	attemptUUID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	raw := attemptUUID.String()
	body := map[string]any{"resolved_by_attempt_id": raw}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hypotheses/"+fixtureID+"/verify", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	got, ok := parseResolveRequest(w, req)
	if !ok {
		t.Fatalf("parseResolveRequest returned !ok; body=%s", w.Body.String())
	}
	want := ResolveParams{
		AttemptID:         &attemptUUID,
		ObservationID:     nil,
		ResolutionSummary: "",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ResolveParams mismatch (-want +got):\n%s", diff)
	}
}

func TestParseResolveRequest_HappyPath_SummaryOnly(t *testing.T) {
	t.Parallel()

	body := map[string]any{"resolution_summary": "solved_independent on attempt #2, 8 min"}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hypotheses/"+fixtureID+"/verify", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	got, ok := parseResolveRequest(w, req)
	if !ok {
		t.Fatalf("parseResolveRequest returned !ok; body=%s", w.Body.String())
	}
	want := ResolveParams{
		AttemptID:         nil,
		ObservationID:     nil,
		ResolutionSummary: "solved_independent on attempt #2, 8 min",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ResolveParams mismatch (-want +got):\n%s", diff)
	}
}
