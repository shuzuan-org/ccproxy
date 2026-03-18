.PHONY: build build-linux run test clean docker-build docker-run docker-push release

VERSION ?= dev
LDFLAGS := -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=$(VERSION) -s -w"

build:
	go build $(LDFLAGS) -o bin/ccproxy ./cmd/ccproxy

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/ccproxy-linux-amd64 ./cmd/ccproxy

run: build
	./bin/ccproxy

test:
	go test ./... -v -race

clean:
	rm -rf bin/ data/

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t saloolooo/ccproxy:$(VERSION) -t saloolooo/ccproxy:latest .

docker-run:
	docker run --rm -p 80:80 -p 443:443 -v ccproxy_data:/data --hostname ccproxy saloolooo/ccproxy:latest

docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t saloolooo/ccproxy:$(VERSION) -t saloolooo/ccproxy:latest \
		--push .

release:
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then echo "Usage: make release VERSION=x.y.z"; exit 1; fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION) || (echo "Push failed, removing local tag"; git tag -d v$(VERSION); exit 1)
