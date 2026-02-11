package tools

import (
	"testing"
)

func TestResult_Success(t *testing.T) {
	t.Run("with map data", func(t *testing.T) {
		data := map[string]any{"path": "/tmp/test", "size": 100}
		result := Result{Status: StatusSuccess, Data: data}

		if result.Status != StatusSuccess {
			t.Errorf("Result{...}.Status = %v, want %v", result.Status, StatusSuccess)
		}
		if result.Data == nil {
			t.Fatal("Result{...}.Data is nil, want non-nil")
		}
		dataMap, ok := result.Data.(map[string]any)
		if !ok {
			t.Fatalf("Result{...}.Data type = %T, want map[string]any", result.Data)
		}
		if dataMap["path"] != "/tmp/test" {
			t.Errorf("Result{...}.Data[\"path\"] = %v, want %q", dataMap["path"], "/tmp/test")
		}
	})

	t.Run("with nil data", func(t *testing.T) {
		result := Result{Status: StatusSuccess}

		if result.Status != StatusSuccess {
			t.Errorf("Result{...}.Status = %v, want %v", result.Status, StatusSuccess)
		}
		if result.Data != nil {
			t.Errorf("Result{...}.Data = %v, want nil", result.Data)
		}
	})
}

func TestResult_Error(t *testing.T) {
	tests := []struct {
		name    string
		code    ErrorCode
		message string
	}{
		{name: "security error", code: ErrCodeSecurity, message: "access denied"},
		{name: "not found error", code: ErrCodeNotFound, message: "file not found"},
		{name: "execution error", code: ErrCodeExecution, message: "executing command"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Result{
				Status: StatusError,
				Error:  &Error{Code: tt.code, Message: tt.message},
			}

			if result.Status != StatusError {
				t.Errorf("Result{...}.Status = %v, want %v", result.Status, StatusError)
			}
			if result.Data != nil {
				t.Errorf("Result{...}.Data = %v, want nil", result.Data)
			}
			if result.Error == nil {
				t.Fatal("Result{...}.Error is nil, want non-nil")
			}
			if result.Error.Code != tt.code {
				t.Errorf("Result{...}.Error.Code = %v, want %v", result.Error.Code, tt.code)
			}
			if result.Error.Message != tt.message {
				t.Errorf("Result{...}.Error.Message = %q, want %q", result.Error.Message, tt.message)
			}
		})
	}
}

func TestResult_ErrorWithDetails(t *testing.T) {
	details := map[string]any{
		"command": "ls",
		"output":  "permission denied",
	}

	result := Result{
		Status: StatusError,
		Error: &Error{
			Code:    ErrCodeExecution,
			Message: "executing command",
			Details: details,
		},
	}

	if result.Status != StatusError {
		t.Errorf("Result{...}.Status = %v, want %v", result.Status, StatusError)
	}
	if result.Error == nil {
		t.Fatal("Result{...}.Error is nil, want non-nil")
	}
	if result.Error.Details == nil {
		t.Error("Result{...}.Error.Details is nil, want non-nil")
	}
	detailsMap, ok := result.Error.Details.(map[string]any)
	if !ok {
		t.Fatalf("Result{...}.Error.Details type = %T, want map[string]any", result.Error.Details)
	}
	if detailsMap["command"] != "ls" {
		t.Errorf("Result{...}.Error.Details[\"command\"] = %v, want %q", detailsMap["command"], "ls")
	}
}

func TestStatusConstants(t *testing.T) {
	if StatusSuccess != "success" {
		t.Errorf("StatusSuccess = %q, want %q", StatusSuccess, "success")
	}
	if StatusError != "error" {
		t.Errorf("StatusError = %q, want %q", StatusError, "error")
	}
}

func TestErrorCodeConstants(t *testing.T) {
	codes := map[ErrorCode]string{
		ErrCodeSecurity:   "SecurityError",
		ErrCodeNotFound:   "NotFound",
		ErrCodePermission: "PermissionDenied",
		ErrCodeIO:         "IOError",
		ErrCodeExecution:  "ExecutionError",
		ErrCodeTimeout:    "TimeoutError",
		ErrCodeNetwork:    "NetworkError",
		ErrCodeValidation: "ValidationError",
	}

	for code, want := range codes {
		if string(code) != want {
			t.Errorf("ErrorCode(%q) = %q, want %q", code, string(code), want)
		}
	}
}
