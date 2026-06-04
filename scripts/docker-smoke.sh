#!/usr/bin/env bash
# Smoke-test the container contract without starting live BACnet I/O.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tag="${BACNET_MCP_DOCKER_TAG:-${IMAGE_TAG:-bacnet-mcp:local}}"
target="${BACNET_MCP_DOCKER_TARGET:-distroless}"

docker run --rm "${tag}" --help >/dev/null
docker run --rm "${tag}" \
  --config /etc/bacnet-mcp/bacnet-mcp.json \
  --print-config >/dev/null

runtime_user="$(docker image inspect "${tag}" --format '{{.Config.User}}')"
case "${target}:${runtime_user}" in
  distroless:65532:65532|runtime:bacnet) ;;
  *)
    echo "unexpected runtime user for target '${target}': '${runtime_user}'" >&2
    exit 1
    ;;
esac

echo "docker smoke ok: ${tag} (${target})"
