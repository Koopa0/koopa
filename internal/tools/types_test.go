package tools

import (
	"testing"
)

func TestResult_Success(t *testing.T) {
	t.Run("with map data", func(t *testing.T) {
		data := map[string]any{"path": "/tmp/test", "size": 100}
		result := Result{Status: StatusSuccess, Data: data}

		if result.Status != StatusSuccess {
			t.Errorf("Status = %v, want %v", result.Status, StatusSuccess)
		}
		if result.Data == nil {
			t.Fatal("Data is nil, want non-nil")
		}
		dataMap, ok := result.Data.(map[string]any)
		if !ok {
			t.Fatalf("Data type = %T, want map[string]any", result.Data)
		}
		if dataMap["path"] != "/tmp/test" {
			t.Errorf("Data[path] = %v, want /tmp/test", dataMap["path"])
		}
	})

	t.Run("with nil data", func(t *testing.T) {
		result := Result{Status: StatusSuccess}

		if result.Status != StatusSuccess {
			t.Errorf("Status = %v, want %v", result.Status, StatusSuccess)
		}
		if result.Data != nil {
			t.Errorf("Data = %v, want nil", result.Data)
		}
	})
}

func TestResult_Error(t *testing.T) {
	tests := []struct {
		name    string
		code    ErrorCode
		message string
	}{
		{"security error", ErrCodeSecurity, "access denied"},
		{"not found error", ErrCodeNotFound, "file not found"},
		{"execution error", ErrCodeExecution, "command failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Result{
				Status: StatusError,
				Error:  &Error{Code: tt.code, Message: tt.message},
			}

			if result.Status != StatusError {
				t.Errorf("Status = %v, want %v", result.Status, StatusError)
			}
			if result.Data != nil {
				t.Errorf("Data = %v, want nil", result.Data)
			}
			if result.Error == nil {
				t.Fatal("Error is nil, want non-nil")
			}
			if result.Error.Code != tt.code {
				t.Errorf("Error.Code = %v, want %v", result.Error.Code, tt.code)
			}
			if result.Error.Message != tt.message {
				t.Errorf("Error.Message = %v, want %v", result.Error.Message, tt.message)
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
			Message: "command failed",
			Details: details,
		},
	}

	if result.Status != StatusError {
		t.Errorf("Status = %v, want %v", result.Status, StatusError)
	}
	if result.Error == nil {
		t.Fatal("Error is nil, want non-nil")
	}
	if result.Error.Details == nil {
		t.Error("Error.Details is nil, want non-nil")
	}
	detailsMap, ok := result.Error.Details.(map[string]any)
	if !ok {
		t.Fatalf("Error.Details type = %T, want map[string]any", result.Error.Details)
	}
	if detailsMap["command"] != "ls" {
		t.Errorf("Error.Details[command] = %v, want ls", detailsMap["command"])
	}
}

func TestStatusConstants(t *testing.T) {
	if StatusSuccess != "success" {
		t.Errorf("StatusSuccess = %v, want success", StatusSuccess)
	}
	if StatusError != "error" {
		t.Errorf("StatusError = %v, want error", StatusError)
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

	for code, expected := range codes {
		if string(code) != expected {
			t.Errorf("ErrorCode %v = %v, want %v", code, string(code), expected)
		}
	}
}
