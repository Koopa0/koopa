// Package main is the entry point for the Koopa CLI application.
package main

import (
	"fmt"
	"os"

	"github.com/koopa0/koopa-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
