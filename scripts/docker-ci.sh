#!/usr/bin/env bash
# Build and validate local Docker runtime and distroless images.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

runtime_tag="${BACNET_MCP_DOCKER_RUNTIME_TAG:-bacnet-mcp:runtime}"
distroless_tag="${BACNET_MCP_DOCKER_DISTROLESS_TAG:-bacnet-mcp:distroless}"

BACNET_MCP_DOCKER_TAG="${runtime_tag}" \
BACNET_MCP_DOCKER_TARGET=runtime \
  scripts/docker-build.sh
BACNET_MCP_DOCKER_TAG="${runtime_tag}" \
BACNET_MCP_DOCKER_TARGET=runtime \
  scripts/docker-smoke.sh

BACNET_MCP_DOCKER_TAG="${distroless_tag}" \
BACNET_MCP_DOCKER_TARGET=distroless \
  scripts/docker-build.sh
BACNET_MCP_DOCKER_TAG="${distroless_tag}" \
BACNET_MCP_DOCKER_TARGET=distroless \
  scripts/docker-smoke.sh
