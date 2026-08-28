use std::{net::ToSocketAddrs, str::FromStr, sync::Arc};

use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{connection::Connection, error::RouteError, router::EchoRouter, runner::run, routes::CreateNewUserData};
use echo_types::{PasswordProtected, Secret, User, UserSettings, UserState};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};

#[tokio::main]
async fn main() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/17/bin")
    );

    let options = PgConnectOptions::from_str(&temp.connection_uri())?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    {
        let mut conn = pool.acquire().await?;

        let query = include_str!("../../SCHEMA.sql");

        conn.execute(query).await?;
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ]).unwrap();

    let cert = CertificateDer::from(cert.der().to_vec());

    let key = PrivatePkcs8KeyDer::from_pem_slice(signing_key.serialize_pem().as_bytes())?;

    tokio::spawn(run(
        "localhost:4433",
        vec![cert.clone()],
        key.into(),
        10,
        Arc::new(EchoRouter::new().await),
        pool
    ));

    let into_socket_addr = |raw: &str| raw
        .to_socket_addrs()
        .expect("failed to resolve IP")
        .next()
        .expect("failed to resolve IP - none found");

    let local = into_socket_addr("localhost:10092");

    let mut root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

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

    let parent = endpoint
        .connect(into_socket_addr("localhost:4433"), "localhost")?
        .await?;

    let mut conn = Connection::open_bi(&parent).await?;

    conn.send(&"users.create").await?;

    let secret = Secret::random();

    let data = CreateNewUserData {
        username: "axo".to_string(),
        secret: PasswordProtected::new(&secret, "6767"),
        state: secret.encrypt(&UserState {
            settings: UserSettings {
                cache_secret_for: 0,
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

    conn = Connection::open_bi(&parent).await?;

    conn.send(&"users.get").await?;

    conn.send(&user.id).await?;

    let maybe_user2: std::result::Result<User, RouteError> = conn.receive().await?;

    let user2 = maybe_user2?;

    println!("{}", user == user2);

    Ok(())
}
