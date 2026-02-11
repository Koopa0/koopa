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
//	pathValidator, err := security.NewPath([]string{"/safe/dir"})
//	if _, err := pathValidator.Validate(userInput); err != nil {
//	    return fmt.Errorf("invalid path: %w", err)
//	}
//
// Command Validator: Blocks dangerous shell commands and prevents command injection.
//
//	cmdValidator := security.NewCommand()
//	if err := cmdValidator.Validate(cmd, args); err != nil {
//	    return fmt.Errorf("dangerous command: %w", err)
//	}
//
// Dangerous commands blocked include: rm -rf, sudo, shutdown, dd, mkfs,
// format, and other destructive operations.
//
// URL Validator: Prevents SSRF attacks by blocking requests to private networks
// and cloud metadata endpoints.
//
//	urlValidator := security.NewURL()
//	if err := urlValidator.Validate(rawURL); err != nil {
//	    return fmt.Errorf("SSRF attempt blocked: %w", err)
//	}
//	// Use SafeTransport for DNS-rebinding protection
//	client := &http.Client{Transport: urlValidator.SafeTransport()}
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
//	if err := envValidator.Validate(key); err != nil {
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
//	pathVal, _ := security.NewPath([]string{workDir})
//	cmdVal := security.NewCommand()
//	urlVal := security.NewURL()
//	envVal := security.NewEnv()
//
//	// Pass to tool constructors during initialization
//	fileTools, _ := tools.NewFile(pathVal, logger)
//	systemTools, _ := tools.NewSystem(cmdVal, envVal, logger)
//	networkTools, _ := tools.NewNetwork(urlVal, logger)
//
// # Configuration
//
// The URL validator uses SafeTransport for DNS-resolution-level SSRF protection:
//
//	urlValidator := security.NewURL()
//	client := &http.Client{Transport: urlValidator.SafeTransport()}
//
// Other validators use secure defaults and require no configuration.
//
// # Error Handling
//
// Validators intentionally both log and return errors. This is a deliberate
// exception to the "handle errors once" rule: security events require an
// audit trail (via logging) AND must propagate the error to callers so they
// can deny the operation. Removing either side would create a security gap.
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
