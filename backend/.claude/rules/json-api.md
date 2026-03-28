---
paths:
  - "**/*handler*.go"
  - "**/*http*.go"
  - "**/*api*.go"
  - "**/*response*.go"
  - "**/*request*.go"
---

# JSON API Rules

## Request Decoding Constraints

- MUST limit request body size with `http.MaxBytesReader` (default: 1MB)
- MUST use `json.NewDecoder` for request bodies (streams)
- NEVER use `json.Unmarshal` with `io.ReadAll` for HTTP requests (unbounded memory)

## Response Encoding Constraints

See: http-server.md for response header requirements (`Content-Type`, `X-Content-Type-Options`).

- MUST handle `json.Encoder.Encode` errors (log, don't panic)

## Nil vs Empty Slice (Critical for JSON)

- API responses MUST return `[]`, NEVER `null` for list fields
- MUST initialize empty slices before encoding: `orders := []Order{}`
- See: database.md for sqlc `emit_empty_slices` setting

## JSON Tags

- MUST use `snake_case` for JSON field names
- MUST tag all exported fields that are serialized
- NEVER define custom `MarshalJSON` unless genuinely necessary

## Error Response Constraints

See: http-server.md for error response rules (4xx/5xx handling, error leakage prevention).

## Validation Constraints

- ALL validation MUST happen in handler, BEFORE calling store
- Store assumes valid input — no validation in data layer
- NEVER use validation libraries (go-playground/validator)
- NEVER add `Validate()` methods — keep validation inline

## Handler Helpers

- `decode`, `encode`, `respondError` are **unexported** in each feature's `handler.go`
- Duplication across features is intentional (Go proverb: "A little copying is better than a little dependency")

## Shared API Package (`internal/api`)

`internal/api` is the **one sanctioned shared package** for cross-cutting HTTP response helpers:
- `api.Encode` — JSON response writer with Content-Type and nosniff headers
- `api.Error` — structured error response
- `api.HandleError` — sentinel error → HTTP status mapping via `api.ErrMap`
- `api.Response` / `api.PagedResponse` — envelope types
- `api.ParsePagination` — pagination parameter parsing

This exists because every handler needs the same response envelope, error format, and pagination logic. Duplicating these across 20+ packages would create drift. Feature-specific helpers (decode, validate) stay unexported in each feature's handler.go.

## Pagination Constraints

- `limit` MUST default to 20, max 100
- Values outside range MUST return 400
- Empty result MUST be `{"data": []}`, NEVER `{"data": null}`
- Query params MUST use `snake_case`: `?user_id=123`

## Reference

For implementation examples, see `/http-server` skill.
