.PHONY: build run test clean

VERSION ?= dev
LDFLAGS := -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/ccproxy ./cmd/ccproxy

run: build
	./bin/ccproxy start

test:
	go test ./... -v -race

clean:
	rm -rf bin/ data/
