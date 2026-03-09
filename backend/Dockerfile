FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/app

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/server /usr/local/bin/server
COPY --from=builder /app/migrations /migrations

EXPOSE 8080

ENTRYPOINT ["server"]
