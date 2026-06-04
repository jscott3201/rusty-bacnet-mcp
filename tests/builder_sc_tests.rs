#![cfg(feature = "sc")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bacnet_mcp::builder::GatewayBuilder;
use bacnet_mcp::config::GatewayConfig;
use bacnet_transport::sc_frame::Vmac;
use bacnet_transport::sc_hub::ScHub;
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[tokio::test]
async fn sc_runtime_build_requires_readable_client_certificate() {
    let config = GatewayConfig::from_json(include_str!("../examples/bacnet-mcp.sc.json")).unwrap();
    config.validate().unwrap();

    let err = match GatewayBuilder::new(config).build().await {
        Ok(_) => panic!("placeholder SC config must not build without certificate files"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("failed to read SC client cert"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn sc_runtime_connects_server_and_client_nodes_to_local_hub() {
    let certs = generate_test_certs();
    let cert_dir = TempCertDir::new(&certs);
    let (mut hub, hub_uri) = start_sc_hub_mtls(&certs, [0x02, 0, 0, 0, 0, 0xff]).await;

    let json = format!(
        r#"{{
            "device": {{
                "instance": 389001,
                "name": "SC Smoke Gateway",
                "vendor_id": 999
            }},
            "transports": {{
                "sc": {{
                    "hub_uri": "{hub_uri}",
                    "cert": "{}",
                    "key": "{}",
                    "ca": "{}",
                    "client_vmac": "02:00:00:00:00:01",
                    "server_vmac": "02:00:00:00:00:02",
                    "network_number": 2
                }}
            }}
        }}"#,
        cert_dir.client_cert.display(),
        cert_dir.client_key.display(),
        cert_dir.ca_cert.display(),
    );
    let config = GatewayConfig::from_json(&json).unwrap();
    config.validate().unwrap();

    let built = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        GatewayBuilder::new(config).build(),
    )
    .await
    .expect("SC gateway build should not hang")
    .expect("SC gateway should connect to local hub");

    assert_eq!(built.server_mac, [0x02, 0, 0, 0, 0, 0x02]);
    assert_eq!(
        built.state.require_client().unwrap().transport_name(),
        "sc",
        "GatewayState should expose the SC client runtime"
    );

    drop(built);
    hub.stop().await;
}

struct CertMaterial {
    ca_cert_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn generate_test_certs() -> CertMaterial {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("empty SANs should be valid");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_params = CertificateParams::new(vec!["bacnet-mcp-client".into()]).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    CertMaterial {
        ca_cert_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

async fn start_sc_hub_mtls(certs: &CertMaterial, hub_vmac: Vmac) -> (ScHub, String) {
    let tls_config = make_server_tls_config_mtls(certs);
    let acceptor = TlsAcceptor::from(tls_config);
    let hub = ScHub::start("127.0.0.1:0", acceptor, hub_vmac)
        .await
        .unwrap();
    let addr = hub.local_addr().unwrap();
    (hub, format!("wss://127.0.0.1:{}", addr.port()))
}

fn make_server_tls_config_mtls(certs: &CertMaterial) -> Arc<rustls::ServerConfig> {
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certs.server_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(certs.server_key_pem.as_bytes()).unwrap();

    let mut client_auth_roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certs.ca_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    for cert in ca_certs {
        client_auth_roots.add(cert).unwrap();
    }

    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
            .build()
            .unwrap();

    Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, key)
            .unwrap(),
    )
}

struct TempCertDir {
    root: PathBuf,
    ca_cert: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl TempCertDir {
    fn new(certs: &CertMaterial) -> Self {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let ca_cert = write_pem(&root, "ca.pem", &certs.ca_cert_pem);
        let client_cert = write_pem(&root, "client.pem", &certs.client_cert_pem);
        let client_key = write_pem(&root, "client.key", &certs.client_key_pem);
        Self {
            root,
            ca_cert,
            client_cert,
            client_key,
        }
    }
}

impl Drop for TempCertDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("bacnet-mcp-sc-test-{}-{nanos}", std::process::id()))
}

fn write_pem(root: &Path, name: &str, contents: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, contents).unwrap();
    path
}
