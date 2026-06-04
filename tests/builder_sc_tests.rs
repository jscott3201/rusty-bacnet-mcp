#![cfg(feature = "sc")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bacnet_mcp::builder::GatewayBuilder;
use bacnet_mcp::config::GatewayConfig;
#[cfg(feature = "mcp")]
use bacnet_mcp::mcp::discovery;
use bacnet_transport::sc_frame::Vmac;
use bacnet_transport::sc_hub::ScHub;
use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

static SC_HUB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let _guard = SC_HUB_TEST_LOCK.lock().await;
    let certs = generate_test_certs();
    let cert_dir = TempCertDir::new(&certs);
    let (mut hub, hub_uri) = start_sc_hub_mtls(&certs, [0x02, 0, 0, 0, 0, 0xff]).await;

    let built = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        build_sc_gateway(&hub_uri, &cert_dir),
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

#[tokio::test]
async fn sc_embedded_hub_builds_and_connects_local_nodes() {
    let _guard = SC_HUB_TEST_LOCK.lock().await;
    let certs = generate_test_certs();
    let cert_dir = TempCertDir::new(&certs);

    let mut built = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        build_embedded_sc_gateway(&cert_dir),
    )
    .await
    .expect("embedded SC gateway build should not hang")
    .expect("embedded SC gateway should start hub and connect local nodes");

    let hub_addr = built
        .sc_hub
        .as_ref()
        .and_then(|hub| hub.local_addr())
        .expect("embedded hub should expose local address");
    assert_ne!(hub_addr.port(), 0);
    assert_eq!(built.server_mac, [0x02, 0, 0, 0, 0, 0x02]);
    assert_eq!(built.state.require_client().unwrap().transport_name(), "sc");

    if let Some(hub) = built.sc_hub.as_mut() {
        hub.stop().await;
    }
}

#[tokio::test]
#[cfg(feature = "mcp")]
async fn sc_register_device_accepts_vmac_and_rejects_bip_socket_address() {
    let _guard = SC_HUB_TEST_LOCK.lock().await;
    let certs = generate_test_certs();
    let cert_dir = TempCertDir::new(&certs);
    let (mut hub, hub_uri) = start_sc_hub_mtls(&certs, [0x02, 0, 0, 0, 0, 0xff]).await;
    let built = build_sc_gateway(&hub_uri, &cert_dir)
        .await
        .expect("SC gateway should connect to local hub");

    let result = discovery::register_device_impl(
        &built.state,
        discovery::RegisterDeviceParams {
            device_instance: 389_099,
            address: "02:00:00:00:00:42".into(),
        },
    )
    .await
    .unwrap();
    assert!(result.contains("Registered device 389099"));

    let devices = discovery::list_known_devices_impl(&built.state)
        .await
        .unwrap();
    assert!(devices.contains("Instance 389099"), "got: {devices}");
    assert!(devices.contains("02, 00, 00, 00, 00, 42"), "got: {devices}");

    let err = discovery::register_device_impl(
        &built.state,
        discovery::RegisterDeviceParams {
            device_instance: 389_100,
            address: "127.0.0.1:47808".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("invalid BACnet/SC VMAC address"), "got: {err}");

    let err = discovery::discover_devices_impl(
        &built.state,
        discovery::DiscoverParams {
            low_instance: None,
            high_instance: None,
            timeout_seconds: Some(0),
            target: Some("127.0.0.1:47808".into()),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("invalid BACnet/SC VMAC address"), "got: {err}");

    drop(built);
    hub.stop().await;
}

async fn build_sc_gateway(
    hub_uri: &str,
    cert_dir: &TempCertDir,
) -> Result<bacnet_mcp::builder::BuiltGateway, bacnet_mcp::builder::BuildError> {
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
    GatewayBuilder::new(config).build().await
}

async fn build_embedded_sc_gateway(
    cert_dir: &TempCertDir,
) -> Result<bacnet_mcp::builder::BuiltGateway, bacnet_mcp::builder::BuildError> {
    let json = format!(
        r#"{{
            "device": {{
                "instance": 389001,
                "name": "SC Embedded Gateway",
                "vendor_id": 999
            }},
            "transports": {{
                "sc": {{
                    "listen": "127.0.0.1:0",
                    "cert": "{}",
                    "key": "{}",
                    "ca": "{}",
                    "hub_vmac": "02:00:00:00:00:ff",
                    "client_vmac": "02:00:00:00:00:01",
                    "server_vmac": "02:00:00:00:00:02",
                    "network_number": 2
                }}
            }}
        }}"#,
        cert_dir.server_cert.display(),
        cert_dir.server_key.display(),
        cert_dir.ca_cert.display(),
    );
    let config = GatewayConfig::from_json(&json).unwrap();
    config.validate().unwrap();
    GatewayBuilder::new(config).build().await
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
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl TempCertDir {
    fn new(certs: &CertMaterial) -> Self {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let ca_cert = write_pem(&root, "ca.pem", &certs.ca_cert_pem);
        let server_cert = write_pem(&root, "server.pem", &certs.server_cert_pem);
        let server_key = write_pem(&root, "server.key", &certs.server_key_pem);
        let client_cert = write_pem(&root, "client.pem", &certs.client_cert_pem);
        let client_key = write_pem(&root, "client.key", &certs.client_key_pem);
        Self {
            root,
            ca_cert,
            server_cert,
            server_key,
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
