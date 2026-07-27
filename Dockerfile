# build
FROM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 appuser

WORKDIR /app

COPY --from=builder /out/api /app/api

USER appuser

# PORT e demais configs vêm do .env via docker compose (env_file).
# Fallback interno da app: 8080 (internal/config).
EXPOSE 8080

ENTRYPOINT ["/app/api"]
