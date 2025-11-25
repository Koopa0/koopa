// Package security provides security validators for protecting against common vulnerabilities.
//
// # Overview
//
// This package implements validators that prevent security issues such as:
//   - Path traversal attacks (CWE-22)
//   - Command injection (CWE-78)
//   - Server-Side Request Forgery (SSRF) (CWE-918)
//   - Information disclosure through environment variables
//
// All validators are designed to be integrated into tool implementations,
// providing defense-in-depth for AI agent operations.
//
// # Validators
//
// Path Validator: Prevents directory traversal and ensures file operations
// stay within allowed boundaries.
//
//	pathValidator := security.NewPath()
//	if err := pathValidator.ValidatePath(userInput); err != nil {
//	    return fmt.Errorf("invalid path: %w", err)
//	}
//
// Command Validator: Blocks dangerous shell commands and prevents command injection.
//
//	cmdValidator := security.NewCommand()
//	if err := cmdValidator.ValidateCommand(cmd, args); err != nil {
//	    return fmt.Errorf("dangerous command: %w", err)
//	}
//
// Dangerous commands blocked include: rm -rf, sudo, shutdown, dd, mkfs,
// format, and other destructive operations.
//
// HTTP Validator: Prevents SSRF attacks by blocking requests to private networks
// and cloud metadata endpoints.
//
//	httpValidator := security.NewHTTP()
//	if err := httpValidator.ValidateURL(url); err != nil {
//	    return fmt.Errorf("SSRF attempt blocked: %w", err)
//	}
//	// Use the validator's HTTP client for safe requests
//	resp, err := httpValidator.Client().Get(url)
//
// Blocked targets include:
//   - Private IP ranges (127.0.0.1, 192.168.x.x, 10.x.x.x)
//   - localhost and local domain names
//   - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
//
// Environment Variable Validator: Protects sensitive environment variables
// from unauthorized access.
//
//	envValidator := security.NewEnv()
//	if err := envValidator.ValidateEnvAccess(key); err != nil {
//	    return fmt.Errorf("access to sensitive variable blocked: %w", err)
//	}
//
// Blocks access to variables containing: KEY, SECRET, TOKEN, PASSWORD, etc.
//
// # Design Philosophy
//
// All validators follow these principles:
//   - Fail-secure: When in doubt, deny access
//   - Explicit allowlists: Use allowlists instead of denylists where possible
//   - Clear error messages: Help developers understand why validation failed
//   - Zero configuration: Work securely out of the box
//
// # Integration Example
//
//	// Create validators
//	pathVal := security.NewPath()
//	cmdVal := security.NewCommand()
//	httpVal := security.NewHTTP()
//	envVal := security.NewEnv()
//
//	// Pass to toolsets during initialization
//	fileToolset := tools.NewFileToolset(pathVal)
//	systemToolset := tools.NewSystemToolset(cmdVal, envVal)
//	networkToolset := tools.NewNetworkToolset(httpVal)
//
// # Configuration
//
// The HTTP validator supports configuration for response size limits,
// timeouts, and redirect limits:
//
//	httpValidator := security.NewHTTP()
//	// Default: 10MB max response, 30s timeout, 10 redirects
//	client := httpValidator.Client()
//
// Other validators use secure defaults and require no configuration.
//
// # Testing
//
// Each validator includes comprehensive tests covering:
//   - Valid inputs that should pass
//   - Attack vectors that should be blocked
//   - Edge cases and boundary conditions
//
// See *_test.go files for security test coverage.
package security
