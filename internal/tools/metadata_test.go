package tools

import (
	"testing"
)

func TestDangerLevel_String(t *testing.T) {
	tests := []struct {
		level DangerLevel
		want  string
	}{
		{DangerLevelSafe, "Safe"},
		{DangerLevelWarning, "Warning"},
		{DangerLevelDangerous, "Dangerous"},
		{DangerLevelCritical, "Critical"},
		{DangerLevel(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("DangerLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetToolMetadata(t *testing.T) {
	// Verify all expected tools are present
	expectedTools := []string{
		ToolReadFile, ToolWriteFile, ToolListFiles, ToolDeleteFile, ToolGetFileInfo,
		ToolCurrentTime, ToolExecuteCommand, ToolGetEnv,
		ToolWebSearch, ToolWebFetch,
		"request_confirmation",
	}

	for _, toolName := range expectedTools {
		t.Run("has_"+toolName, func(t *testing.T) {
			meta, exists := GetToolMetadata(toolName)
			if !exists {
				t.Errorf("Expected tool %s to be in metadata", toolName)
				return
			}

			// Verify metadata fields are populated
			if meta.Category == "" {
				t.Errorf("Tool %s has empty Category", toolName)
			}
			if meta.Description == "" {
				t.Errorf("Tool %s has empty Description", toolName)
			}
		})
	}
}

func TestGetToolMetadata_DangerLevels(t *testing.T) {
	tests := []struct {
		toolName    string
		wantLevel   DangerLevel
		description string
	}{
		// Safe tools (read-only)
		{ToolReadFile, DangerLevelSafe, "read-only file access"},
		{ToolListFiles, DangerLevelSafe, "read-only directory listing"},
		{ToolGetFileInfo, DangerLevelSafe, "read-only file metadata"},
		{ToolCurrentTime, DangerLevelSafe, "read-only system time"},
		{ToolWebSearch, DangerLevelSafe, "read-only web search"},
		{ToolWebFetch, DangerLevelSafe, "read-only HTTP requests"},
		{ToolGetEnv, DangerLevelSafe, "read-only environment variables"},
		{"request_confirmation", DangerLevelSafe, "safety mechanism"},

		// Warning tools (modifies state, reversible)
		{ToolWriteFile, DangerLevelWarning, "file modification"},

		// Dangerous tools (irreversible/destructive)
		{ToolDeleteFile, DangerLevelDangerous, "file deletion"},
		{ToolExecuteCommand, DangerLevelDangerous, "arbitrary command execution"},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			meta, exists := GetToolMetadata(tt.toolName)
			if !exists {
				t.Fatalf("Tool %s not found in metadata", tt.toolName)
			}

			if meta.DangerLevel != tt.wantLevel {
				t.Errorf("Tool %s: DangerLevel = %v (%s), want %v (%s) - %s",
					tt.toolName,
					meta.DangerLevel, meta.DangerLevel.String(),
					tt.wantLevel, tt.wantLevel.String(),
					tt.description)
			}
		})
	}
}

func TestGetToolMetadata_RequiresConfirmation(t *testing.T) {
	tests := []struct {
		toolName         string
		wantConfirmation bool
		description      string
	}{
		// Safe tools (no confirmation needed)
		{ToolReadFile, false, "read-only operations don't need confirmation"},
		{ToolListFiles, false, "read-only operations don't need confirmation"},
		{ToolGetFileInfo, false, "read-only operations don't need confirmation"},
		{ToolCurrentTime, false, "read-only operations don't need confirmation"},
		{ToolWebSearch, false, "read-only operations don't need confirmation"},
		{ToolWebFetch, false, "read-only operations don't need confirmation"},
		{ToolGetEnv, false, "read-only operations don't need confirmation"},
		{"request_confirmation", false, "request_confirmation itself doesn't need confirmation"},

		// Warning/Dangerous tools (confirmation required)
		{ToolWriteFile, true, "file modification needs confirmation"},
		{ToolDeleteFile, true, "file deletion needs confirmation"},
		{ToolExecuteCommand, true, "command execution needs confirmation"},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			meta, exists := GetToolMetadata(tt.toolName)
			if !exists {
				t.Fatalf("Tool %s not found in metadata", tt.toolName)
			}

			if meta.RequiresConfirmation != tt.wantConfirmation {
				t.Errorf("Tool %s: RequiresConfirmation = %v, want %v - %s",
					tt.toolName,
					meta.RequiresConfirmation,
					tt.wantConfirmation,
					tt.description)
			}
		})
	}
}

func TestGetAllToolMetadata(t *testing.T) {
	allMeta := GetAllToolMetadata()

	// Verify we have all 11 tools (5 file + 3 system + 2 network + 1 meta)
	expectedCount := 11
	if len(allMeta) != expectedCount {
		t.Errorf("GetAllToolMetadata() returned %d tools, expected %d", len(allMeta), expectedCount)
	}

	// Verify it returns a copy (mutation doesn't affect original)
	originalLen := len(allMeta)
	allMeta["testTool"] = ToolMetadata{} // Mutate the returned map

	allMeta2 := GetAllToolMetadata()
	if len(allMeta2) != originalLen {
		t.Errorf("GetAllToolMetadata() should return a copy, but mutation affected original")
	}
	if _, exists := allMeta2["testTool"]; exists {
		t.Errorf("GetAllToolMetadata() should return a copy, but mutation affected original")
	}
}

func TestIsDangerous(t *testing.T) {
	tests := []struct {
		toolName string
		want     bool
	}{
		// Dangerous tools
		{ToolDeleteFile, true},
		{ToolExecuteCommand, true},

		// Safe tools
		{ToolReadFile, false},
		{ToolListFiles, false},
		{ToolGetFileInfo, false},
		{ToolCurrentTime, false},
		{ToolWebSearch, false},
		{ToolWebFetch, false},
		{ToolGetEnv, false},
		{"request_confirmation", false},

		// Warning tools
		{ToolWriteFile, false},

		// Unknown tools (fail-safe to false)
		{"unknownTool", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := IsDangerous(tt.toolName); got != tt.want {
				t.Errorf("IsDangerous(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestRequiresConfirmation(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		params   map[string]any
		want     bool
	}{
		// Static confirmation requirements
		{"delete_file always requires confirmation", ToolDeleteFile, nil, true},
		{"execute_command always requires confirmation", ToolExecuteCommand, nil, true},
		{"read_file never requires confirmation", ToolReadFile, nil, false},

		// Dynamic confirmation based on params (write_file)
		{"write_file to /tmp is warning level", ToolWriteFile, map[string]any{"path": "/tmp/test.txt"}, true},
		{"write_file to /etc escalates to dangerous", ToolWriteFile, map[string]any{"path": "/etc/passwd"}, true},
		{"write_file to /usr escalates to dangerous", ToolWriteFile, map[string]any{"path": "/usr/bin/test"}, true},
		{"write_file to current dir is warning level", ToolWriteFile, map[string]any{"path": "./test.txt"}, true},

		// Unknown tools
		{"unknown tool returns false", "unknownTool", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RequiresConfirmation(tt.toolName, tt.params); got != tt.want {
				t.Errorf("RequiresConfirmation(%q, %v) = %v, want %v",
					tt.toolName, tt.params, got, tt.want)
			}
		})
	}
}

func TestGetDangerLevel(t *testing.T) {
	tests := []struct {
		toolName string
		want     DangerLevel
	}{
		{ToolDeleteFile, DangerLevelDangerous},
		{ToolExecuteCommand, DangerLevelDangerous},
		{ToolWriteFile, DangerLevelWarning},
		{ToolReadFile, DangerLevelSafe},
		{"unknownTool", DangerLevelSafe}, // Fail-safe default
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := GetDangerLevel(tt.toolName); got != tt.want {
				t.Errorf("GetDangerLevel(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestListToolsByDangerLevel(t *testing.T) {
	tests := []struct {
		level         DangerLevel
		expectedCount int
		description   string
	}{
		{DangerLevelSafe, 8, "safe tools: read_file, list_files, get_file_info, current_time, web_search, web_fetch, get_env, request_confirmation"},
		{DangerLevelWarning, 1, "warning tools: write_file"},
		{DangerLevelDangerous, 2, "dangerous tools: delete_file, execute_command"},
		{DangerLevelCritical, 0, "critical tools: none yet"},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			tools := ListToolsByDangerLevel(tt.level)

			if len(tools) != tt.expectedCount {
				t.Errorf("ListToolsByDangerLevel(%v) returned %d tools, want %d - %s",
					tt.level, len(tools), tt.expectedCount, tt.description)

				// List what we got for debugging
				t.Logf("Got tools:")
				for _, tool := range tools {
					t.Logf("  - %s (%s)", tool.Category, tool.Description)
				}
			}

			// Verify all returned tools have the correct danger level
			for _, tool := range tools {
				if tool.DangerLevel != tt.level {
					t.Errorf("Tool has DangerLevel %v, expected %v", tool.DangerLevel, tt.level)
				}
			}
		})
	}
}

func TestGetToolMetadata_Categories(t *testing.T) {
	expectedCategories := map[string][]string{
		"File":    {ToolReadFile, ToolWriteFile, ToolListFiles, ToolDeleteFile, ToolGetFileInfo},
		"System":  {ToolCurrentTime, ToolExecuteCommand, ToolGetEnv},
		"Network": {ToolWebSearch, ToolWebFetch},
		"Meta":    {"request_confirmation"},
	}

	for category, expectedTools := range expectedCategories {
		t.Run("category_"+category, func(t *testing.T) {
			var foundTools []string

			for _, toolName := range expectedTools {
				meta, exists := GetToolMetadata(toolName)
				if !exists {
					t.Errorf("Tool %s not found in metadata", toolName)
					continue
				}

				if meta.Category != category {
					t.Errorf("Tool %s: Category = %s, want %s", toolName, meta.Category, category)
				} else {
					foundTools = append(foundTools, toolName)
				}
			}

			if len(foundTools) != len(expectedTools) {
				t.Errorf("Category %s: found %d tools, expected %d",
					category, len(foundTools), len(expectedTools))
			}
		})
	}
}

func TestWriteFile_IsDangerousFunc(t *testing.T) {
	meta, ok := GetToolMetadata(ToolWriteFile)
	if !ok {
		t.Fatal("writeFile metadata not found")
	}

	if meta.IsDangerousFunc == nil {
		t.Fatal("writeFile should have IsDangerousFunc defined")
	}

	tests := []struct {
		name   string
		params map[string]any
		want   bool
	}{
		{"normal path", map[string]any{"path": "/tmp/test.txt"}, false},
		{"current dir", map[string]any{"path": "./test.txt"}, false},
		{"home dir", map[string]any{"path": "/home/user/test.txt"}, false},
		{"/etc path", map[string]any{"path": "/etc/passwd"}, true},
		{"/usr path", map[string]any{"path": "/usr/bin/test"}, true},
		{"/bin path", map[string]any{"path": "/bin/sh"}, true},
		{"/sbin path", map[string]any{"path": "/sbin/init"}, true},
		{"/sys path", map[string]any{"path": "/sys/test"}, true},
		{"/proc path", map[string]any{"path": "/proc/test"}, true},
		{"no path param", map[string]any{}, false},
		{"nil params", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := meta.IsDangerousFunc(tt.params)
			if got != tt.want {
				t.Errorf("IsDangerousFunc(%v) = %v, want %v", tt.params, got, tt.want)
			}
		})
	}
}

func TestExecuteCommand_IsDangerousFunc(t *testing.T) {
	meta, ok := GetToolMetadata(ToolExecuteCommand)
	if !ok {
		t.Fatal("executeCommand metadata not found")
	}

	if meta.IsDangerousFunc == nil {
		t.Fatal("executeCommand should have IsDangerousFunc defined")
	}

	// executeCommand should always return true (all commands are dangerous)
	tests := []map[string]any{
		{"command": "ls"},
		{"command": "rm -rf /"},
		{"command": "echo hello"},
		{},
		nil,
	}

	for i, params := range tests {
		t.Run("case_"+string(rune(i+'0')), func(t *testing.T) {
			got := meta.IsDangerousFunc(params)
			if !got {
				t.Errorf("IsDangerousFunc(%v) = false, want true (all commands are dangerous)", params)
			}
		})
	}
}
