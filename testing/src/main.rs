use std::{net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::Arc};

use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{connection::Connection, error::RouteError, router::EchoRouter, runner::run, routes::CreateNewUserData};
use echo_types::{PasswordProtected, Secret, User, UserSettings, UserState};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};

// Helper function to turn a raw address into a [`SocketAddr`].
fn into_socket_addr(addr: impl ToSocketAddrs) -> Result<SocketAddr> {
    let socket_addr = addr
        .to_socket_addrs()
        .context("failed to resolve IP")?
        .next()
        .context("failed to resolve IP - none found")?;

    Ok(socket_addr)
}

/// Configure the client and then connect to the QUIC endpoint on the server.
async fn connect_to_server(
    local_addr: impl ToSocketAddrs,
    server_addr: impl ToSocketAddrs,
    cert: CertificateDer<'static>
) -> Result<quinn::Connection> {
    let local = into_socket_addr(local_addr)?;

    let mut root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    // Add the certificate to the list of certificates the client trusts.
    root_store.add(cert)?;

    if root_store.is_empty() {
        bail!("no TLS server certificates");
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = quinn::ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(client_crypto)?
        )
    );

    let mut endpoint = quinn::Endpoint::client(local)?;

    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(into_socket_addr(server_addr)?, "localhost")?
        .await?;

    Ok(conn)
}

#[tokio::main]
async fn main() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/17/bin")
    );

    let options = PgConnectOptions::from_str(&temp.connection_uri())?
        .statement_cache_capacity(0);

    // Open a pool of connections to the database.
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    {
        let mut conn = pool.acquire().await?;

        let query = include_str!("../../SCHEMA.sql");

        // pgtemp opens a blank database, so all our tables need to be created.
        conn.execute(query).await?;
    }

    // Create a basic TLS certificate for testing purposes.
    // Typically, these would be loaded from files on disk.
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ]).unwrap();

    let cert = CertificateDer::from(cert.der().to_vec());

    let key = PrivatePkcs8KeyDer::from_pem_slice(signing_key.serialize_pem().as_bytes())?;

    // Start the server up
    tokio::spawn(run(
        "localhost:4433",
        cert.clone(),
        key.into(),
        10,
        Arc::new(EchoRouter::new()),
        pool
    ));

    // Connect to the server
    let parent = &connect_to_server(
        "localhost:10092",
        "localhost:4433",
        cert
    ).await?;

    // Connect to the API
    let mut conn = Connection::open_bi(parent).await?;

    // Choose to create a user account
    conn.send(&"users.create").await?;

    let secret = Secret::random();
    let password = "6767";

    let data = CreateNewUserData {
        username: "alice".to_string(),
        secret: PasswordProtected::new(&secret, password),
        state: secret.encrypt(&UserState {
            settings: UserSettings {
                logout_after: 0,
                enable_read_receipts: true,
                enable_typing_indicators: true,
                ignore_future_requests_from: vec![]
            }
        }),
        signature_verifier: secret.into()
    };

    conn.send(&data).await?;

    let maybe_user: std::result::Result<User, RouteError> = conn.receive().await?;

    let user = maybe_user?;

    conn.close()?;

    // Open a new connection to the API
    conn = Connection::open_bi(parent).await?;

    // Choose to get a user account instead
    conn.send(&"users.get").await?;

    conn.send(&user.id).await?;

    let maybe_user2: std::result::Result<User, RouteError> = conn.receive().await?;

    let user2 = maybe_user2?;

    // Check the two user accounts are the same
    assert_eq!(user, user2);

    // Check that after fetching, we can still decrypt the user's
    // secret if we have the right password
    assert!(user2.secret.unlock(password).is_ok());

    println!("assertions passed!");

    Ok(())
}
