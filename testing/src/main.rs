use std::{collections::HashMap, net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::Arc};

use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{error::RouteError, router::EchoRouter, routes::{CreateFriendRequestData, CreateNewUserData, FriendRequestKeys, FriendRequestSessionData, UnestablishedDmSession}, runner::run, stream::Stream};
use echo_types::{FriendRequest, PasswordProtected, Secret, SnowflakeID, User, UserSettings, UserState};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};
use vodozemac::olm::{Account, OlmMessage, SessionConfig};

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

    // Hand off execution on the route to the caller
    let out = stream_fn(&mut stream).await?;

    stream.close()?;

    Ok(out)
}

const DEFAULT_PASSWORD: &str = "6767";

/// Perform server authentication using the given account.
/// Because this is a testing environment, the password
/// will always stay the same.
pub async fn authenticate_as(
    stream: &mut Stream,
    user: &User
) -> Result<()> {
    let user_secret = user.secret.unlock(DEFAULT_PASSWORD)?;

    let user_signed_id = user_secret.sign(user.id);

    stream.send(&user_signed_id).await?;

    Ok(())
}

type RouteResult<T> = std::result::Result<T, RouteError>;

/// Create an account with a given username on the server,
/// returning the created user object.
async fn create_account(
    parent: &quinn::Connection,
    username: &str
) -> Result<User> {
    access_route(parent, "users.create", async |stream| {
        let secret = Secret::random();
        let olm_account = Account::new();

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
            signature_verifier: secret.into(),
            olm_account: secret.encrypt(&olm_account.pickle()),
            olm_public_key: olm_account.curve25519_key()
        };

        stream.send(&data).await?;

        let user: User = stream.receive::<RouteResult<_>>().await??;

        Ok(user)
    }).await
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

    let alice_secret = alice.secret.unlock(DEFAULT_PASSWORD)?;
    let mut alice_olm: Account = alice_secret.decrypt(&alice.olm_account)?.into();

    let bob_secret = bob.secret.unlock(DEFAULT_PASSWORD)?;
    let bob_olm: Account = bob_secret.decrypt(&bob.olm_account)?.into();

    // Alice sends Bob a friend request
    access_route(parent, "users.friends.requests.create", async |stream| {
        authenticate_as(stream, &alice).await?;

        let result = alice_olm.generate_one_time_keys(1);

        alice_olm.mark_keys_as_published();

        let one_time_key = result.created[0];

        let data = CreateFriendRequestData {
            receiver: bob.id,
            one_time_key,
            new_account: alice_secret.encrypt(&alice_olm.pickle())
        };

        stream.send(&data).await?;

        Ok(())
    }).await?;

    // Test that the friend request appeared for Bob
    access_route(parent, "users.friends.requests.get", async |stream| {
        authenticate_as(stream, &bob).await?;

        let requests: Vec<FriendRequest> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            requests.iter().any(|req| req.sender == alice.id),
            "bob did not get a friend request from alice"
        );

        Ok(())
    }).await?;

    // Bob now accepts Alice's friend request and makes an Olm session.
    let bob_to_alice = access_route(parent, "users.friends.requests.accept", async |stream| {
        authenticate_as(stream, &bob).await?;

        stream.send(&alice.id).await?;

        let FriendRequestKeys {
            public_key,
            one_time_key
        } = stream.receive::<RouteResult<_>>().await??;

        let mut session = bob_olm.create_outbound_session(
            SessionConfig::version_1(),
            public_key,
            one_time_key
        )?;

        let OlmMessage::PreKey(pre_key_message) = session.encrypt([])? else {
            unreachable!()
        };

        let data = FriendRequestSessionData {
            session: bob_secret.encrypt(&session.pickle()),
            pre_key_message
        };

        stream.send(&data).await?;

        Ok(session)
    }).await?;

    // Alice checks her DM session inbox to fully complete the channel.
    let alice_to_bob = access_route(parent, "inbox.sessions.dm.establish", async |stream| {
        authenticate_as(stream, &alice).await?;

        let entries: HashMap<SnowflakeID, UnestablishedDmSession> = stream.receive::<RouteResult<_>>().await??;

        let UnestablishedDmSession {
            user_olm_public_key,
            pre_key_message
        } = &entries[&bob.id];

        let session = alice_olm.create_inbound_session(
            SessionConfig::version_1(),
            *user_olm_public_key,
            pre_key_message
        )?.session;

        let mut sessions = HashMap::new();

        sessions.insert(bob.id, bob_secret.encrypt(&session.pickle()));

        stream.send(&sessions).await?;

        stream.send(&alice_secret.encrypt(&alice_olm.pickle())).await?;

        Ok(session)
    }).await?;

    println!("assertions passed!");

    Ok(())
}
