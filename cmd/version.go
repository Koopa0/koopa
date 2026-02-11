package cmd

import "fmt"

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/koopa0/koopa/cmd.Version=1.0.0"
//
// Default value "dev" indicates a development build.
var Version = "dev"

// runVersion displays version information.
func runVersion() {
	fmt.Printf("Koopa v%s\n", Version)
}
