FROM golang:1.26.1-alpine3.23 AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build-time identity injected via -ldflags. BUILD_SHA / BUILD_VERSION can
# be passed as --build-arg in CI; defaults derive from the in-tree git state
# so a local `docker build .` still stamps a meaningful SHA.
ARG BUILD_SHA
ARG BUILD_VERSION=v0.0.0-dev
RUN SHA="${BUILD_SHA:-$(git rev-parse HEAD 2>/dev/null || echo dev)}" \
    && BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    && CGO_ENABLED=0 go build \
        -ldflags="-X github.com/Koopa0/koopa/internal/build.SHA=${SHA} -X github.com/Koopa0/koopa/internal/build.BuiltAt=${BUILT_AT} -X github.com/Koopa0/koopa/internal/build.Version=${BUILD_VERSION}" \
        -o /app/server ./cmd/app

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S app -G app

COPY --from=builder /app/server /usr/local/bin/server
COPY --from=builder /app/migrations /migrations

USER app

EXPOSE 8080

ENTRYPOINT ["server"]
