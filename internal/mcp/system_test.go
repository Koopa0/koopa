package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCurrentTime_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	result, _, err := server.CurrentTime(context.Background(), &mcp.CallToolRequest{}, tools.CurrentTimeInput{})

	if err != nil {
		t.Fatalf("CurrentTime failed: %v", err)
	}

	if result.IsError {
		t.Errorf("CurrentTime returned error: %v", result.Content)
	}

	// Verify content format
	if len(result.Content) == 0 {
		t.Fatal("CurrentTime returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("CurrentTime content is not TextContent")
	}

	// Should contain JSON with time data
	if !strings.Contains(textContent.Text, "time") {
		t.Errorf("CurrentTime text does not contain 'time' field: %s", textContent.Text)
	}

	// Should contain timestamp
	if !strings.Contains(textContent.Text, "timestamp") {
		t.Errorf("CurrentTime text does not contain 'timestamp' field: %s", textContent.Text)
	}

	// Should contain iso8601
	if !strings.Contains(textContent.Text, "iso8601") {
		t.Errorf("CurrentTime text does not contain 'iso8601' field: %s", textContent.Text)
	}
}

func TestExecuteCommand_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	result, _, err := server.ExecuteCommand(context.Background(), &mcp.CallToolRequest{}, tools.ExecuteCommandInput{
		Command: "echo",
		Args:    []string{"hello", "world"},
	})

	if err != nil {
		t.Fatalf("ExecuteCommand failed: %v", err)
	}

	if result.IsError {
		t.Errorf("ExecuteCommand returned error: %v", result.Content)
	}

	// Verify output contains "hello world"
	if len(result.Content) == 0 {
		t.Fatal("ExecuteCommand returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("ExecuteCommand content is not TextContent")
	}

	if !strings.Contains(textContent.Text, "hello world") {
		t.Errorf("ExecuteCommand output does not contain 'hello world': %s", textContent.Text)
	}
}

func TestExecuteCommand_DangerousCommandBlocked(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Try to execute a dangerous command
	result, _, err := server.ExecuteCommand(context.Background(), &mcp.CallToolRequest{}, tools.ExecuteCommandInput{
		Command: "rm",
		Args:    []string{"-rf", "/"},
	})

	// Should not return Go error, but MCP error result
	if err != nil {
		t.Fatalf("ExecuteCommand returned Go error: %v", err)
	}

	if !result.IsError {
		t.Error("ExecuteCommand should return IsError=true for dangerous command")
	}
}

func TestExecuteCommand_CommandNotFound(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	result, _, err := server.ExecuteCommand(context.Background(), &mcp.CallToolRequest{}, tools.ExecuteCommandInput{
		Command: "nonexistent_command_12345",
		Args:    []string{},
	})

	// Should not return Go error, but MCP error result
	if err != nil {
		t.Fatalf("ExecuteCommand returned Go error: %v", err)
	}

	if !result.IsError {
		t.Error("ExecuteCommand should return IsError=true for non-existent command")
	}
}

func TestGetEnv_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Set a test environment variable using t.Setenv for automatic cleanup
	testKey := "MCP_TEST_VAR"
	testValue := "test_value_123"
	t.Setenv(testKey, testValue)

	result, _, err := server.GetEnv(context.Background(), &mcp.CallToolRequest{}, tools.GetEnvInput{
		Key: testKey,
	})

	if err != nil {
		t.Fatalf("GetEnv failed: %v", err)
	}

	if result.IsError {
		t.Errorf("GetEnv returned error: %v", result.Content)
	}

	// Verify output contains the value
	if len(result.Content) == 0 {
		t.Fatal("GetEnv returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("GetEnv content is not TextContent")
	}

	if !strings.Contains(textContent.Text, testValue) {
		t.Errorf("GetEnv output does not contain value: %s", textContent.Text)
	}
}

func TestGetEnv_NotSet(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	result, _, err := server.GetEnv(context.Background(), &mcp.CallToolRequest{}, tools.GetEnvInput{
		Key: "NONEXISTENT_VAR_12345",
	})

	if err != nil {
		t.Fatalf("GetEnv failed: %v", err)
	}

	if result.IsError {
		t.Errorf("GetEnv returned error for unset var: %v", result.Content)
	}

	// Verify output indicates variable is not set
	if len(result.Content) == 0 {
		t.Fatal("GetEnv returned empty content")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("GetEnv content is not TextContent")
	}

	// JSON output should indicate isSet: false
	if !strings.Contains(textContent.Text, `"isSet":false`) {
		t.Errorf("GetEnv output should contain isSet:false for unset var: %s", textContent.Text)
	}
}

func TestGetEnv_SensitiveVariableBlocked(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Try to access a sensitive variable
	sensitiveKeys := []string{"AWS_SECRET_KEY", "API_TOKEN", "DATABASE_PASSWORD"}

	for _, key := range sensitiveKeys {
		t.Run(key, func(t *testing.T) {
			result, _, err := server.GetEnv(context.Background(), &mcp.CallToolRequest{}, tools.GetEnvInput{
				Key: key,
			})

			// Should not return Go error, but MCP error result
			if err != nil {
				t.Fatalf("GetEnv returned Go error: %v", err)
			}

			if !result.IsError {
				t.Errorf("GetEnv should return IsError=true for sensitive variable %s", key)
			}
		})
	}
}
