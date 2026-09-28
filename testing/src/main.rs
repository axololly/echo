use std::{net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::Arc};

use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{error::RouteError, router::EchoRouter, routes::CreateNewUserData, runner::run, stream::Stream};
use echo_types::{Friend, FriendRequest, PasswordProtected, Secret, User, UserSettings, UserState};
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

/// Access a route in the API, then communicate with the server
/// under that same route using the same [`Stream`].
async fn access_route<R>(
    parent: &quinn::Connection,
    route: &str,
    mut stream_fn: impl AsyncFnMut(&mut Stream) -> Result<R>
) -> Result<R> {
    let mut stream = Stream::open_bi(parent).await?;

    println!("accessing route {route:?}");

    // Handle routing to reduce boilerplate
    stream.send(&route).await?;

    stream.receive::<RouteResult<()>>().await??;

    // Hand off execution on the route to the caller
    let out = stream_fn(&mut stream).await?;

    stream.close()?;

    Ok(out)
}

const DEFAULT_PASSWORD: &str = "6767";

type RouteResult<T> = std::result::Result<T, RouteError>;

/// Create an account with a given username on the server,
/// returning the created user object.
async fn create_account(
    parent: &quinn::Connection,
    username: &str
) -> Result<User> {
    let secret = Secret::random();

    let account = access_route(parent, "users.create", async |stream| {
        let data = CreateNewUserData {
            username: username.to_string(),
            secret: PasswordProtected::new(&secret, DEFAULT_PASSWORD),
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

        stream.send(&data).await?;

        let user: User = stream.receive::<RouteResult<_>>().await??;

        Ok(user)
    }).await?;

    access_route(parent, "login", async |stream| {
        let signed_id = secret.sign(account.id);

        stream.send(&signed_id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    Ok(account)
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

    // Make our accounts
    let alice = create_account(parent, "alice").await?;
    let bob = create_account(parent, "bob").await?;

    // Alice sends Bob a friend request
    access_route(parent, "users.friends.requests.create", async |stream| {
        stream.send(&bob.id).await?;

        Ok(())
    }).await?;

    // Test that the friend request appeared for Bob
    access_route(parent, "users.friends.requests.get", async |stream| {
        let requests: Vec<FriendRequest> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            requests.iter().any(|req| req.sender == alice.id),
            "bob did not get a friend request from alice"
        );

        Ok(())
    }).await?;

    // Bob now accepts Alice's friend request
    access_route(parent, "users.friends.requests.accept", async |stream| {
        stream.send(&alice.id).await?;

        Ok(())
    }).await?;

    // Alice checks her friends list
    access_route(parent, "users.friends.get", async |stream| {
        let friends: Vec<Friend> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            friends.iter().any(|f| f.id == bob.id),
            "alice did not get bob as a friend"
        );

        Ok(())
    }).await?;

    // Bob checks his friends list
    access_route(parent, "users.friends.get", async |stream| {
        let friends: Vec<Friend> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            friends.iter().any(|f| f.id == alice.id),
            "bob did not get alice as a friend"
        );

        Ok(())
    }).await?;

    println!("assertions passed!");

    Ok(())
}
