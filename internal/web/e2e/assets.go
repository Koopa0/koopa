//go:build e2e

// Package e2e provides embedded assets for E2E testing.
// These assets are only included in test builds (go test -tags=e2e).
package e2e

import _ "embed"

// AxeCoreJS contains the axe-core accessibility testing library.
// Version: 4.10.2
// Source: https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js
//
//go:embed assets/axe.min.js
var AxeCoreJS string
