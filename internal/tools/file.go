package tools

// file.go defines file operation tools with security validation.
//
// Provides 5 file tools: readFile, writeFile, listFiles, deleteFile, getFileInfo.
// All operations use security.PathValidator to prevent path traversal attacks (CWE-22).
// File permissions: 0600 for created files, 0750 for directories.
//
// Architecture: Genkit closures act as thin adapters that convert JSON input
// to Handler method calls. Business logic lives in testable Handler methods.

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// registerFileTools registers filesystem-related tools
// handler contains all business logic for file operations
func registerFileTools(g *genkit.Genkit, handler *Handler) {
	// 1. Read file
	genkit.DefineTool(
		g,
		"readFile",
		"Read the complete content of any text-based file. "+
			"Use this to analyze source code, read documentation, check configuration files, or review logs. "+
			"Supports absolute and relative paths. Validates paths for security. "+
			"Returns the full text content of the file. "+
			"Supported formats: Programming languages (.go, .py, .js, .ts, .java, .c, .cpp, .h, .rs, .rb, .php, .swift, .kt, etc.), "+
			"Markup/Config (.html, .xml, .json, .yaml, .yml, .toml, .ini, .env, .properties), "+
			"Documentation (.md, .txt, .rst, .adoc, LICENSE, README, CHANGELOG), "+
			"Scripts (.sh, .bash, .zsh, .ps1, .bat), "+
			"Web (.css, .scss, .sass, .less, .vue, .jsx, .tsx), "+
			"Data (.csv, .sql, .graphql), "+
			"Build/Container (Dockerfile, Makefile, CMakeLists.txt, docker-compose.yml, .dockerignore, Containerfile), "+
			"Package managers (package.json, go.mod, go.sum, Cargo.toml, requirements.txt, Gemfile, Pipfile, pom.xml, build.gradle), "+
			"CI/CD (.gitlab-ci.yml, Jenkinsfile, .travis.yml, .circleci/config.yml, .github/workflows/*.yml), "+
			"Git/Editor (.gitignore, .gitattributes, .editorconfig), "+
			"and any other UTF-8 encoded text file.",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File path to read (absolute or relative to current directory). Supports any text file format including Dockerfile, Makefile, and files without extensions. Examples: 'README.md', './src/main.go', 'Dockerfile', 'Makefile', '.gitignore', 'docker-compose.yml'"`
		},
		) (string, error) {
			return handler.ReadFile(input.Path)
		},
	)

	// 2. Write file
	genkit.DefineTool(
		g,
		"writeFile",
		"Write or create any text-based file with the specified content. "+
			"Use this to create new files, save generated content, or update existing files. "+
			"WARNING: This will overwrite existing files! Automatically creates parent directories. "+
			"Sets secure permissions (owner read/write only). "+
			"Supports all text file formats: Programming languages (.go, .py, .js, .ts, .java, .c, .cpp, .h, .rs, .rb, .php, .swift, .kt, etc.), "+
			"Markup/Config (.html, .xml, .json, .yaml, .yml, .toml, .ini, .env, .properties), "+
			"Documentation (.md, .txt, .rst, .adoc, LICENSE, README, CHANGELOG), "+
			"Scripts (.sh, .bash, .zsh, .ps1, .bat), "+
			"Web (.css, .scss, .sass, .less, .vue, .jsx, .tsx), "+
			"Data (.csv, .sql, .graphql), "+
			"Build/Container (Dockerfile, Makefile, CMakeLists.txt, docker-compose.yml, .dockerignore, Containerfile), "+
			"Package managers (package.json, go.mod, Cargo.toml, requirements.txt, Gemfile, Pipfile, pom.xml, build.gradle), "+
			"CI/CD (.gitlab-ci.yml, Jenkinsfile, .travis.yml, .circleci/config.yml, .github/workflows/*.yml), "+
			"Git/Editor (.gitignore, .gitattributes, .editorconfig), "+
			"and any other UTF-8 text format. "+
			"Use for: creating source code, saving reports, writing configurations, generating documentation, creating build files, setting up containers.",
		func(ctx *ai.ToolContext, input struct {
			Path    string `json:"path" jsonschema_description:"File path to write (absolute or relative). Parent directories will be created if needed. Supports any text file format including Dockerfile, Makefile, and files without extensions. Examples: 'output.txt', './src/main.rs', 'Dockerfile', 'Makefile', '.gitignore', 'docker-compose.yml'"`
			Content string `json:"content" jsonschema_description:"The complete text content to write. Will overwrite existing file content if file exists. Supports any UTF-8 text including source code, markup, config, Dockerfiles, Makefiles, etc."`
		},
		) (string, error) {
			return handler.WriteFile(input.Path, input.Content)
		},
	)

	// 3. List directory contents
	genkit.DefineTool(
		g,
		"listFiles",
		"List all files and subdirectories in a directory. "+
			"Use this to explore directory structure, find files of specific types (e.g., .md, .go, .ts, .py files), or understand project organization. "+
			"This tool shows ALL files in the directory - you can filter by extension or pattern in your response to the user. "+
			"Returns a formatted list with [File] and [Directory] prefixes. "+
			"Does not recursively list subdirectories (only shows immediate children). "+
			"Useful for: exploring project structure, finding .md/.go/.ts files, understanding codebase layout. "+
			"IMPORTANT: Always use this tool (not executeCommand with 'ls') for listing directory contents.",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"Directory path to list (absolute or relative). Use '.' for current directory. Examples: '.', './src', '/home/user/project'"`
		},
		) (string, error) {
			return handler.ListFiles(input.Path)
		},
	)

	// 4. Delete file
	genkit.DefineTool(
		g,
		"deleteFile",
		"Delete a file permanently from the filesystem. "+
			"WARNING: This action is irreversible! File will be permanently deleted. "+
			"Use with extreme caution. Ask for user confirmation before deleting important files. "+
			"Does not delete directories (use this only for files). "+
			"Use for: removing temporary files, cleaning up generated files, deleting outdated files.",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File path to delete (absolute or relative). This will permanently delete the file! Examples: 'temp.txt', './logs/old.log'"`
		},
		) (string, error) {
			return handler.DeleteFile(input.Path)
		},
	)

	// 5. Get file information
	genkit.DefineTool(
		g,
		"getFileInfo",
		"Get detailed metadata about a file or directory without reading its content. "+
			"Returns: name, size, type (file/directory), modification time, permissions. "+
			"Use this when you need file information but don't need to read the actual content. "+
			"Useful for: checking file size before reading, verifying file exists, checking modification dates, inspecting permissions.",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File or directory path to inspect (absolute or relative). Examples: 'README.md', './src', '/var/log/app.log'"`
		},
		) (string, error) {
			return handler.GetFileInfo(input.Path)
		},
	)
}
