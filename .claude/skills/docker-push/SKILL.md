---
name: docker-push
description: Build and push ccproxy multi-arch Docker image to Docker Hub. Use when user asks to push Docker image, build Docker image, update Docker Hub, or deploy container image.
---

# Docker Push

Build and push `saloolooo/ccproxy` multi-arch image (linux/amd64 + linux/arm64) to Docker Hub.

## Prerequisites

- Docker Hub account: `saloolooo`
- Buildx builder: `ccproxy-builder` (already configured with multi-arch support)

## Workflow

1. **Run tests first** to ensure code is healthy:

```bash
make test
```

2. **Build and push** multi-arch image in one step:

```bash
docker buildx build --builder ccproxy-builder \
  --platform linux/amd64,linux/arm64 \
  -t saloolooo/ccproxy:latest \
  --push .
```

To include a version tag:

```bash
docker buildx build --builder ccproxy-builder \
  --platform linux/amd64,linux/arm64 \
  -t saloolooo/ccproxy:latest \
  -t saloolooo/ccproxy:VERSION \
  --push .
```

3. **Verify** the pushed manifest:

```bash
docker buildx imagetools inspect saloolooo/ccproxy:latest
```

## Notes

- Always use `--push` with buildx multi-arch builds; `docker push` separately does not work for manifest lists.
- The `ccproxy-builder` uses `docker-container` driver which supports cross-compilation natively.
- Do NOT use `binn/ccproxy` — that is an incorrect/obsolete namespace.
- Go cross-compilation with `CGO_ENABLED=0` handles arm64 builds without QEMU emulation for the compile step.
