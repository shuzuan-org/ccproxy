# Stage 1: Build ccproxy
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=${VERSION} -s -w" \
    -o /ccproxy ./cmd/ccproxy

# Stage 2: Get Caddy binary
FROM caddy:2-alpine AS caddy

# Stage 3: Runtime
FROM alpine:3
RUN apk add --no-cache ca-certificates

COPY --from=builder /ccproxy /usr/bin/ccproxy
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY docker/entrypoint.sh /entrypoint.sh

ENV USER=ccproxy
WORKDIR /

VOLUME /data
EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
