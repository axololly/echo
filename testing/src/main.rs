use std::{collections::HashMap, net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::Arc};

use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use echo_server::{error::RouteError, events::Event, router::EchoRouter, routes::{CreateFriendRequestData, CreateNewUserData, FriendRequestKeys, FriendRequestSessionData, SendDmMessageData, UnestablishedDmSession}, runner::run, stream::Stream};
use echo_types::{Friend, FriendRequest, Message, MessageBody, PasswordProtected, Secret, SnowflakeID, User, UserSettings, UserState};
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

    stream.receive::<RouteResult<()>>().await??;

    // Hand off execution on the route to the caller
    let out = stream_fn(&mut stream).await.unwrap();

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
    let olm_account = Account::new();

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
            signature_verifier: secret.into(),
            olm_account: secret.encrypt(&olm_account.pickle()),
            olm_public_key: olm_account.curve25519_key()
        };

        stream.send(&data).await?;

        let user: User = stream.receive::<RouteResult<_>>().await??;

        Ok(user)
    }).await?;

    println!("created user {username:?} with ID {}", account.id);

    access_route(parent, "login", async |stream| {
        let signed_id = secret.sign(account.id);

        stream.send(&signed_id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    let event_listener = async |mut stream: Stream, username: String| -> Result<()> {
        // Handle routing to reduce boilerplate
        stream.send(&"events").await?;

        stream.receive::<RouteResult<()>>().await??;

        loop {
            let event: Event = stream.receive::<RouteResult<_>>().await??;

            match event {
                Event::NewDirectMessageFrom(user) => {
                    println!("[event for {username:?}] new DM from {user}");
                },
                Event::UserAcceptedFriendRequest(user) => {
                    println!("[event for {username:?}] {user} accepted the friend request");
                },
                Event::NewFriendRequest(user) => {
                    println!("[event for {username:?}] new friend request from {user}");
                }
            }
        }
    };

    let stream = Stream::open_bi(parent).await?;
    let username = username.to_string();

    tokio::spawn(async move {
        if let Err(e) = event_listener(stream, username).await {
            println!("Error with receiving events on the client-side: {e:?}");
        }
    });

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

    // Both connect to the server
    let alice_conn = &connect_to_server(
        "localhost:10092",
        "localhost:4433",
        cert.clone()
    ).await?;

    let bob_conn = &connect_to_server(
        "localhost:10093",
        "localhost:4433",
        cert
    ).await?;


    // Make our accounts
    let alice = create_account(alice_conn, "alice").await?;
    let bob = create_account(bob_conn, "bob").await?;

    let alice_secret = alice.secret.unlock(DEFAULT_PASSWORD)?;
    let mut alice_olm: Account = alice_secret.decrypt(&alice.olm_account)?.into();

    let bob_secret = bob.secret.unlock(DEFAULT_PASSWORD)?;
    let bob_olm: Account = bob_secret.decrypt(&bob.olm_account)?.into();

    // Alice sends Bob a friend request
    access_route(alice_conn, "users.friends.requests.create", async |stream| {
        let result = alice_olm.generate_one_time_keys(1);

        alice_olm.mark_keys_as_published();

        let one_time_key = result.created[0];

        let data = CreateFriendRequestData {
            receiver: bob.id,
            one_time_key,
            new_account: alice_secret.encrypt(&alice_olm.pickle())
        };

        stream.send(&data).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Test that the friend request appeared for Bob
    access_route(bob_conn, "users.friends.requests.get", async |stream| {
        let requests: Vec<FriendRequest> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            requests.iter().any(|req| req.sender == alice.id),
            "bob did not get a friend request from alice"
        );

        Ok(())
    }).await?;

    // Bob now accepts Alice's friend request and makes an Olm session.
    let mut bob_to_alice = access_route(bob_conn, "users.friends.requests.accept", async |stream| {
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

        stream.receive::<RouteResult<()>>().await??;

        Ok(session)
    }).await?;

    // Alice checks her friends list
    access_route(alice_conn, "users.friends.get", async |stream| {
        let friends: Vec<Friend> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            friends.iter().any(|f| f.id == bob.id),
            "alice did not get bob as a friend"
        );

        Ok(())
    }).await?;

    // Bob checks his friends list
    access_route(bob_conn, "users.friends.get", async |stream| {
        let friends: Vec<Friend> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            friends.iter().any(|f| f.id == alice.id),
            "bob did not get alice as a friend"
        );

        Ok(())
    }).await?;

    // Alice checks her DM session inbox to fully complete the channel.
    let mut alice_to_bob = access_route(alice_conn, "inbox.dm.sessions.establish", async |stream| {
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

        sessions.insert(bob.id, alice_secret.encrypt(&session.pickle()));

        stream.send(&sessions).await?;

        stream.send(&alice_secret.encrypt(&alice_olm.pickle())).await?;

        stream.receive::<RouteResult<
            HashMap<SnowflakeID, UnestablishedDmSession>
        >>().await??;

        stream.receive::<RouteResult<()>>().await??;

        Ok(session)
    }).await?;

    // Alice then decides to send Bob a message with her created session.
    let alice_message = access_route(alice_conn, "dms.messages.send", async |stream| {
        let body = MessageBody {
            content: "hello bob".to_string()
        };

        let secret = Secret::random();

        let key_for_receiver = alice_to_bob.encrypt(secret)?;

        let data = SendDmMessageData {
            receiver: bob.id,
            message_body: secret.encrypt(&body),
            key_for_sender: alice_secret.encrypt(&secret),
            key_for_receiver
        };

        stream.send(&data).await?;

        let message: Message = stream.receive::<RouteResult<_>>().await??;

        Ok(message)
    }).await?;

    // Bob checks his inbox to read it.
    access_route(bob_conn, "inbox.dm.messages.unread", async |stream| {
        let unresolved: HashMap<SnowflakeID, (SnowflakeID, OlmMessage)> = stream.receive::<RouteResult<_>>().await??;

        let (sender, olm) = &unresolved[&alice_message.id];

        assert_eq!(*sender, alice.id);

        let secret: Secret = bob_to_alice
            .decrypt(olm)?
            .as_slice()
            .try_into()?;

        println!(
            "bob read from alice: {:?}",
            secret.decrypt(&alice_message.body)?.content
        );

        let mut resolved = HashMap::new();

        resolved.insert(alice_message.id, alice_secret.encrypt(&secret));

        stream.send(&resolved).await?;

        stream.receive::<RouteResult<
            HashMap<SnowflakeID, (SnowflakeID, OlmMessage)>
        >>().await??;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    println!("assertions passed!");

    Ok(())
}
