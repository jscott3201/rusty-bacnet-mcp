# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.95.0
ARG ALPINE_VERSION=3.22
ARG DISTROLESS_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM docker.io/library/rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS build

ARG FEATURES=bin,sc

WORKDIR /app

RUN apk add --no-cache \
    build-base \
    ca-certificates \
    cmake \
    perl \
    pkgconfig

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked --features "${FEATURES}" \
    && cp target/release/bacnet-mcp /usr/local/bin/bacnet-mcp

FROM docker.io/library/alpine:${ALPINE_VERSION} AS runtime

ARG UID=10001

LABEL org.opencontainers.image.title="bacnet-mcp" \
      org.opencontainers.image.description="MCP server for agentic BACnet workflows" \
      org.opencontainers.image.source="https://github.com/jscott3201/rusty-bacnet-mcp"

RUN apk add --no-cache ca-certificates \
    && adduser -D -H -h /nonexistent -s /sbin/nologin -u "${UID}" bacnet

COPY --from=build /usr/local/bin/bacnet-mcp /usr/local/bin/bacnet-mcp
COPY --chown=bacnet:bacnet examples/bacnet-mcp.container.json /etc/bacnet-mcp/bacnet-mcp.json

USER bacnet
WORKDIR /etc/bacnet-mcp

EXPOSE 3000/tcp
EXPOSE 47808/udp
EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/bacnet-mcp"]
CMD ["--config", "/etc/bacnet-mcp/bacnet-mcp.json", "--transport", "http", "--bind", "0.0.0.0:3000"]

FROM ${DISTROLESS_IMAGE} AS distroless

LABEL org.opencontainers.image.title="bacnet-mcp" \
      org.opencontainers.image.description="MCP server for agentic BACnet workflows" \
      org.opencontainers.image.source="https://github.com/jscott3201/rusty-bacnet-mcp"

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /usr/local/bin/bacnet-mcp /usr/local/bin/bacnet-mcp
COPY --chown=65532:65532 examples/bacnet-mcp.container.json /etc/bacnet-mcp/bacnet-mcp.json

USER 65532:65532
WORKDIR /etc/bacnet-mcp

EXPOSE 3000/tcp
EXPOSE 47808/udp
EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/bacnet-mcp"]
CMD ["--config", "/etc/bacnet-mcp/bacnet-mcp.json", "--transport", "http", "--bind", "0.0.0.0:3000"]
