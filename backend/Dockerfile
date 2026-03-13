FROM golang:1.26.1-alpine3.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/app

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S app -G app

COPY --from=builder /app/server /usr/local/bin/server
COPY --from=builder /app/migrations /migrations

USER app

EXPOSE 8080

ENTRYPOINT ["server"]
