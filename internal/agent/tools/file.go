package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// registerFileTools registers filesystem-related tools
// pathValidator is passed as parameter and captured by closures (Go best practice)
func registerFileTools(g *genkit.Genkit, pathValidator *security.PathValidator) {
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
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			content, err := os.ReadFile(safePath) // #nosec G304 -- path validated by pathValidator above
			if err != nil {
				return "", fmt.Errorf("unable to read file: %w", err)
			}
			return string(content), nil
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
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			// Ensure directory exists (use 0750 permission for better security)
			dir := filepath.Dir(safePath)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return "", fmt.Errorf("unable to create directory: %w", err)
			}

			if err = os.WriteFile(safePath, []byte(input.Content), 0o600); err != nil {
				return "", fmt.Errorf("unable to write file: %w", err)
			}
			return fmt.Sprintf("Successfully wrote file: %s", safePath), nil
		},
	)

	// 3. List directory contents
	genkit.DefineTool(
		g,
		"listFiles",
		"List all files and subdirectories in a directory. "+
			"Use this to explore directory structure, find files, or understand project organization. "+
			"Returns a formatted list with [File] and [Directory] prefixes. "+
			"Does not recursively list subdirectories (only shows immediate children). "+
			"Useful for: exploring project structure, finding specific files, understanding codebase layout.",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"Directory path to list (absolute or relative). Use '.' for current directory. Examples: '.', './src', '/home/user/project'"`
		},
		) (string, error) {
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			entries, err := os.ReadDir(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to read directory: %w", err)
			}

			var result []string
			for _, entry := range entries {
				prefix := "[File]"
				if entry.IsDir() {
					prefix = "[Directory]"
				}
				result = append(result, fmt.Sprintf("%s %s", prefix, entry.Name()))
			}

			return strings.Join(result, "\n"), nil
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
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			if err = os.Remove(safePath); err != nil {
				return "", fmt.Errorf("unable to delete file: %w", err)
			}
			return fmt.Sprintf("Successfully deleted file: %s", safePath), nil
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
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			info, err := os.Stat(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to get file information: %w", err)
			}

			result := fmt.Sprintf("Name: %s\n", info.Name())
			result += fmt.Sprintf("Size: %d bytes\n", info.Size())
			result += fmt.Sprintf("Is directory: %v\n", info.IsDir())
			result += fmt.Sprintf("Modified time: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
			result += fmt.Sprintf("Permissions: %s\n", info.Mode().String())

			return result, nil
		},
	)
}
