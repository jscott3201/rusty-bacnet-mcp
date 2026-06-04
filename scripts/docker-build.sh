#!/usr/bin/env bash
# Build the local bacnet-mcp container image.
#
# Usage:
#   scripts/docker-build.sh
#   BACNET_MCP_DOCKER_TAG=bacnet-mcp:dev scripts/docker-build.sh
#   BACNET_MCP_DOCKER_TARGET=runtime scripts/docker-build.sh

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tag="${BACNET_MCP_DOCKER_TAG:-${IMAGE_TAG:-bacnet-mcp:local}}"
target="${BACNET_MCP_DOCKER_TARGET:-distroless}"
features="${BACNET_MCP_DOCKER_FEATURES:-${FEATURES:-bin,sc}}"

platform_args=()
if [[ -n "${BACNET_MCP_DOCKER_PLATFORM:-}" ]]; then
  platform_args=(--platform "${BACNET_MCP_DOCKER_PLATFORM}")
fi

cache_args=()
case "${BACNET_MCP_DOCKER_CACHE:-}" in
  "")
    ;;
  gha)
    cache_args=(--cache-from type=gha --cache-to type=gha,mode=max)
    ;;
  *)
    echo "unsupported BACNET_MCP_DOCKER_CACHE: ${BACNET_MCP_DOCKER_CACHE}" >&2
    exit 2
    ;;
esac

docker buildx build \
  --load \
  --target "${target}" \
  --build-arg "FEATURES=${features}" \
  --tag "${tag}" \
  "${cache_args[@]}" \
  "${platform_args[@]}" \
  "$@" \
  .
