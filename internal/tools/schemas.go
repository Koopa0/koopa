package tools

// ReadFileInput defines input for readFile tool.
type ReadFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to read (absolute or relative)"`
}

// WriteFileInput defines input for writeFile tool.
type WriteFileInput struct {
	Path    string `json:"path" jsonschema_description:"The file path to write"`
	Content string `json:"content" jsonschema_description:"The content to write to the file"`
}

// ListFilesInput defines input for listFiles tool.
type ListFilesInput struct {
	Path string `json:"path" jsonschema_description:"The directory path to list"`
}

// DeleteFileInput defines input for deleteFile tool.
type DeleteFileInput struct {
	Path string `json:"path" jsonschema_description:"The file path to delete"`
}

// GetFileInfoInput defines input for getFileInfo tool.
type GetFileInfoInput struct {
	Path string `json:"path" jsonschema_description:"The file path to get info for"`
}

// ExecuteCommandInput defines input for executeCommand tool.
type ExecuteCommandInput struct {
	Command string   `json:"command" jsonschema_description:"The command to execute (e.g., 'ls', 'git')"`
	Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments as separate array elements"`
}

// GetEnvInput defines input for getEnv tool.
type GetEnvInput struct {
	Key string `json:"key" jsonschema_description:"The environment variable name"`
}

// HTTPGetInput defines input for httpGet tool.
type HTTPGetInput struct {
	URL string `json:"url" jsonschema_description:"The URL to fetch"`
}

// SearchHistoryInput defines input for searchHistory tool.
type SearchHistoryInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 3)"`
}

// SearchDocumentsInput defines input for searchDocuments tool.
type SearchDocumentsInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 5)"`
}

// SearchSystemKnowledgeInput defines input for searchSystemKnowledge tool.
type SearchSystemKnowledgeInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 3)"`
}

// CurrentTimeInput defines input for currentTime tool (no input needed).
type CurrentTimeInput struct{}
