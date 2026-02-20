.PHONY: build vet lint test test-race test-integration test-fuzz verify clean

# Build binary
build:
	go build -o koopa ./

# Static analysis
vet:
	go vet ./...

# Lint (matches CI: golangci-lint v2.7.1)
lint:
	golangci-lint run ./...

# Unit tests (fast, no database required)
test:
	go test -short ./...

# Unit tests with race detector (matches CI)
test-race:
	go test -short -race ./...

# Integration tests (requires PostgreSQL with pgvector)
test-integration:
	go test -tags=integration -race -timeout 15m ./...

# Run security fuzz targets for 30s each
test-fuzz:
	go test -fuzz=FuzzPathValidation -fuzztime=30s ./internal/security/
	go test -fuzz=FuzzCommandValidation -fuzztime=30s ./internal/security/
	go test -fuzz=FuzzURLValidation -fuzztime=30s ./internal/security/
	go test -fuzz=FuzzSafeDialContext -fuzztime=30s ./internal/security/

# Full verification chain (matches /verify skill)
# Stop at first failure.
verify: build vet lint test-race

# Remove build artifacts
clean:
	rm -f koopa
	go clean -testcache
