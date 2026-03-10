.PHONY: build build-linux run test clean

VERSION ?= dev
LDFLAGS := -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=$(VERSION) -s -w"

build:
	go build $(LDFLAGS) -o bin/ccproxy ./cmd/ccproxy

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/ccproxy-linux-amd64 ./cmd/ccproxy

run: build
	./bin/ccproxy start

test:
	go test ./... -v -race

clean:
	rm -rf bin/ data/
