# koopa build & test targets.
#
# The integration lane requires a Docker daemon: testcontainers-go starts a
# pgvector/pgvector:pg17 container per package (see internal/testdb) and applies
# migrations/ before each suite. CI runs the SAME `make test-integration`
# command so local and CI behaviour cannot drift.

.PHONY: test test-integration verify

# Unit lane: race detector, NO integration build tag. Mirrors the CI `go` job.
test:
	go test -race ./...

# Integration lane: compiles and runs //go:build integration files against a
# real pgvector PostgreSQL (testcontainers). Requires Docker. Mirrors the CI
# `integration` job exactly.
test-integration:
	go test -race -tags integration ./...

# Full local verification: build, vet, unit lane, then the integration lane.
verify:
	go build ./...
	go vet ./...
	go test -race ./...
	go test -race -tags integration ./...
