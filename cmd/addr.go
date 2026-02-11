package cmd

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// parseServeAddr parses and validates the server address from command line arguments.
// Uses flag.FlagSet for standard Go flag parsing, supporting:
//   - koopa serve :8080           (positional)
//   - koopa serve --addr :8080    (flag)
//   - koopa serve -addr :8080     (single dash)
func parseServeAddr() (string, error) {
	const defaultAddr = "127.0.0.1:3400"

	serveFlags := flag.NewFlagSet("serve", flag.ContinueOnError)
	serveFlags.SetOutput(os.Stderr)

	addr := serveFlags.String("addr", defaultAddr, "Server address (host:port)")

	args := []string{}
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	// Check for positional argument first (koopa serve :8080)
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		*addr = args[0]
		args = args[1:]
	}

	if err := serveFlags.Parse(args); err != nil {
		return "", fmt.Errorf("parsing serve flags: %w", err)
	}

	if err := validateAddr(*addr); err != nil {
		return "", fmt.Errorf("invalid address %q: %w", *addr, err)
	}

	return *addr, nil
}

// validateAddr validates the server address format.
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be in host:port format: %w", err)
	}

	if host != "" && host != "localhost" {
		if ip := net.ParseIP(host); ip == nil {
			if strings.ContainsAny(host, " \t\n") {
				return fmt.Errorf("invalid host: %s", host)
			}
		}
	}

	if port == "" {
		return fmt.Errorf("port is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric: %w", err)
	}
	if portNum < 0 || portNum > 65535 {
		return fmt.Errorf("port must be 0-65535 (0 = auto-assign), got %d", portNum)
	}

	return nil
}
