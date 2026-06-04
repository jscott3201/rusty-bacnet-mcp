//! Static Docker deployment contract tests.

const DOCKERFILE: &str = include_str!("../Dockerfile");
const DOCKERIGNORE: &str = include_str!("../.dockerignore");
const DOCKER_BUILD_SCRIPT: &str = include_str!("../scripts/docker-build.sh");
const DOCKER_SMOKE_SCRIPT: &str = include_str!("../scripts/docker-smoke.sh");
const DOCKER_CI_SCRIPT: &str = include_str!("../scripts/docker-ci.sh");
const CONTAINER_CONFIG: &str = include_str!("../examples/bacnet-mcp.container.json");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");

#[test]
fn dockerfile_builds_sc_enabled_release_binary() {
    assert!(
        DOCKERFILE.contains(
            "FROM docker.io/library/rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS build"
        )
    );
    assert!(DOCKERFILE.contains("ARG FEATURES=bin,sc"));
    assert!(DOCKERFILE.contains(r#"cargo build --release --locked --features "${FEATURES}""#));
    assert!(DOCKERFILE.contains("build-base"));
    assert!(DOCKERFILE.contains("cmake"));
    assert!(DOCKERFILE.contains("pkgconfig"));
    assert!(DOCKERFILE.contains("perl"));
    assert!(DOCKERFILE.contains("--mount=type=cache,target=/usr/local/cargo/registry"));
}

#[test]
fn dockerfile_runtime_is_non_root_and_exposes_mcp_and_bacnet_ports() {
    assert!(DOCKERFILE.contains("FROM docker.io/library/alpine:${ALPINE_VERSION} AS runtime"));
    assert!(DOCKERFILE.contains("USER bacnet"));
    assert!(DOCKERFILE.contains("FROM ${DISTROLESS_IMAGE} AS distroless"));
    assert!(DOCKERFILE.contains("USER 65532:65532"));
    assert!(DOCKERFILE.contains(r#"ENTRYPOINT ["/usr/local/bin/bacnet-mcp"]"#));
    assert!(DOCKERFILE.contains(r#""--transport", "http""#));
    assert!(DOCKERFILE.contains(r#""--bind", "0.0.0.0:3000""#));
    assert!(DOCKERFILE.contains("EXPOSE 3000/tcp"));
    assert!(DOCKERFILE.contains("EXPOSE 47808/udp"));
    assert!(DOCKERFILE.contains("EXPOSE 8443/tcp"));
    assert!(DOCKERFILE.contains("SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"));
    assert!(DOCKERFILE.contains("/etc/ssl/certs/ca-certificates.crt"));
}

#[test]
fn dockerignore_excludes_large_local_and_private_agent_state() {
    for expected in [".git", "target", "_goalslogs", "_briefs", ".DS_Store"] {
        assert!(
            DOCKERIGNORE.lines().any(|line| line == expected),
            ".dockerignore missing {expected}"
        );
    }
}

#[test]
fn docker_scripts_preserve_sc_feature_default_and_smoke_user_contract() {
    assert!(
        DOCKER_BUILD_SCRIPT
            .contains(r#"features="${BACNET_MCP_DOCKER_FEATURES:-${FEATURES:-bin,sc}}""#)
    );
    assert!(DOCKER_BUILD_SCRIPT.contains(r#"--target "${target}""#));
    assert!(DOCKER_BUILD_SCRIPT.contains(r#"--build-arg "FEATURES=${features}""#));
    assert!(DOCKER_SMOKE_SCRIPT.contains("--print-config"));
    assert!(DOCKER_SMOKE_SCRIPT.contains("65532:65532"));
    assert!(DOCKER_SMOKE_SCRIPT.contains("runtime:bacnet"));
    assert!(DOCKER_CI_SCRIPT.contains("BACNET_MCP_DOCKER_TARGET=runtime"));
    assert!(DOCKER_CI_SCRIPT.contains("BACNET_MCP_DOCKER_TARGET=distroless"));
}

#[test]
fn container_default_config_is_http_bound_read_only_bip() {
    let json: serde_json::Value = serde_json::from_str(CONTAINER_CONFIG).unwrap();
    assert_eq!(json["mcp"]["read_only"], true);
    assert_eq!(json["mcp"]["http"]["bind"], "0.0.0.0:3000");
    assert_eq!(json["transports"]["bip"]["interface"], "0.0.0.0");
    assert_eq!(json["transports"]["bip"]["port"], 47808);
    assert_eq!(json["transports"]["bip"]["broadcast"], "255.255.255.255");
    assert_eq!(json["transports"]["bip"]["network_number"], 1);
}

#[test]
fn ci_docker_build_is_main_tag_or_manual_only() {
    assert!(CI_WORKFLOW.contains("docker-build"));
    assert!(CI_WORKFLOW.contains("scripts/docker-ci.sh"));
    let docker_job = CI_WORKFLOW
        .split("  docker-build:")
        .nth(1)
        .expect("docker-build job missing")
        .split("\n  deny:")
        .next()
        .expect("docker-build job should precede deny job");
    assert!(docker_job.contains("github.event_name == 'workflow_dispatch'"));
    assert!(docker_job.contains("startsWith(github.ref, 'refs/tags/')"));
    assert!(docker_job.contains("github.ref == 'refs/heads/main'"));
    assert!(docker_job.contains("github.base_ref == 'main'"));
    assert!(!docker_job.contains("refs/heads/development"));
    assert!(!docker_job.contains("github.base_ref == 'development'"));
}
