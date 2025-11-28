// Package main is the entry point for the Koopa CLI application.
package main

import (
	"os"

	"github.com/koopa0/koopa-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
