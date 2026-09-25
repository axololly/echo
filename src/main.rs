mod router;
mod server;
mod stream;
mod varint;

use std::{fmt::Debug, net::{SocketAddr, ToSocketAddrs}, sync::Arc};

use quinn::{ClientConfig, Connection, Endpoint, crypto::rustls::QuicClientConfig, rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject}}};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};

use crate::{router::Router, server::{EchoRoute, run_server}, stream::Stream};

fn into_socket_addrs(addr: impl ToSocketAddrs + Debug) -> Result<SocketAddr, &'static str> {
    addr.to_socket_addrs()
        .context("failed to resolve IP")?
        .next()
        .context("failed to resolve IP - none found")
}

async fn connect_to_server(
    client_addr: impl ToSocketAddrs + Debug,
    server_addr: impl ToSocketAddrs + Debug,
    cert: CertificateDer<'_>
) -> Result<Connection> {
    let mut root_store = RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    root_store.add(cert)?;

    if root_store.is_empty() {
        bail!("no TLS server certificates");
    }

    let mut client_crypto = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(client_crypto)?
        )
    );

    let mut endpoint = Endpoint::client(into_socket_addrs(client_addr)?)?;

    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(into_socket_addrs(server_addr)?, "localhost")?
        .await?;

    Ok(connection)
}

#[tokio::main]
async fn main() -> Result<()> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ])?;

    let server_cert = CertificateDer::from(cert.der().to_vec());

    let server_key = PrivateKeyDer::from_pem_slice(
        signing_key.serialize_pem().as_bytes()
    )?;

    let client_addr = "localhost:6453";
    let server_addr = "localhost:4433";

    let mut router = Router::default();

    router.register(EchoRoute);

    tokio::spawn(run_server(
        server_addr,
        10,
        server_cert.clone(),
        server_key,
        Arc::new(router)
    ));

    let conn = connect_to_server(
        client_addr,
        server_addr,
        server_cert
    ).await?;

    let (send, recv) = conn.open_bi().await?;
    let mut stream = Stream::new(send, recv);

    stream.send(&"echo").await?;

    let response: String = stream.receive().await?;

    println!("response from server: {response:?}");

    Ok(())
}
