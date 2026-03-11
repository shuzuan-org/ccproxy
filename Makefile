.PHONY: build build-linux run test clean docker-build docker-run docker-push

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

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t binn/ccproxy:$(VERSION) -t binn/ccproxy:latest .

docker-run:
	docker run --rm -p 80:80 -p 443:443 -v ccproxy_data:/data --hostname ccproxy binn/ccproxy:latest

docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t binn/ccproxy:$(VERSION) -t binn/ccproxy:latest \
		--push .
