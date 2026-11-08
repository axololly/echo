#![allow(unused)]

use std::{collections::HashMap, net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::{Arc, atomic::{AtomicU16, Ordering}}};

use echo_server::{error::RouteError, events::Event, router::EchoRouter, routes::{CreateNewUserData, EncryptedChatSession, GetMessageHistoryData, MessageHistoryParams, SendMessageData, UnprocessedMessage}, runner::run, stream::Stream};
use echo_types::{BoxPublicKey, Compressed, CryptoBox, Encrypted, Friend, FriendRequest, Message, MessageBody, PasswordProtected, Secret, SnowflakeID, User, UserSettings, UserState};
use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use sqlx::{Executor, postgres::{PgConnectOptions, PgPoolOptions}};
use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionConfig as MegolmSessionConfig};

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

const SERVER_ADDR: &str = "localhost:4433";
static PORT_NUM: AtomicU16 = AtomicU16::new(0);

/// Create an account with a given username on the server,
/// returning the created user object, and authenticating
/// the connection too.
async fn connect_and_create_account(
    username: &str,
    cert: CertificateDer<'static>
) -> Result<(User, quinn::Connection)> {
    let port_num = PORT_NUM.fetch_add(1, Ordering::Relaxed);

    let parent = connect_to_server(
        format!("localhost:{}", 10090 + port_num),
        SERVER_ADDR,
        cert
    ).await?;

    let secret = Secret::random();

    let account = access_route(&parent, "users.create", async |stream| {
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
            box_public_key: secret.into()
        };

        stream.send(&data).await?;

        let user: User = stream.receive::<RouteResult<_>>().await??;

        dbg!((&user.name, user.id));

        Ok(user)
    }).await?;

    println!("created user {username:?} with ID {}", account.id);

    access_route(&parent, "login", async |stream| {
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

            println!("[event for {username:?}] new event: {event:?}");
        }
    };

    let stream = Stream::open_bi(&parent).await?;
    let username = username.to_string();

    tokio::spawn(async move {
        if let Err(e) = event_listener(stream, username).await {
            println!("Error with receiving events on the client-side: {e:?}");
        }
    });

    Ok((account, parent))
}

/// Form a friend request between two users, and get the Olm sessions used
/// to communicate for the pair
async fn establish_friendship(
    user1_data: (&quinn::Connection, &User),
    user2_data: (&quinn::Connection, &User)
) -> Result<SnowflakeID> {
    let (conn1, user1) = user1_data;
    let (conn2, user2) = user2_data;

    access_route(conn1, "users.friends.requests.create", async |stream| {
        stream.send(&user2.id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    access_route(conn2, "users.friends.requests.accept", async |stream| {
        stream.send(&user1.id).await?;

        let conversation_id: SnowflakeID = stream.receive::<RouteResult<_>>().await??;

        Ok(conversation_id)
    }).await
}

async fn send_message(
    user: &User,
    user_conn: &quinn::Connection,
    conversation_id: SnowflakeID,
    message: &str
) -> Result<Message> {
    let user_secret = user.secret.unlock(DEFAULT_PASSWORD)?;

    let message_secret = Secret::random();

    access_route(user_conn, "messages.sessions.ensure", async |stream| {
        stream.send(&conversation_id).await?;

        let needs_uploading: bool = stream.receive::<RouteResult<_>>().await??;

        if !needs_uploading {
            return Ok(());
        }

        let session = GroupSession::new(MegolmSessionConfig::version_1());
        let session_key = session.session_key();

        let other_members: HashMap<SnowflakeID, BoxPublicKey> = stream.receive::<RouteResult<_>>().await??;

        let inbounds = other_members
            .into_iter()
            .map(|(id, pk)| (id, user_secret.box_for(&session_key, pk)))
            .collect();

        let group_chat_session = EncryptedChatSession {
            outbound: user_secret.encrypt(&session.pickle()),
            inbounds
        };

        stream.send(&group_chat_session).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    let mut session: GroupSession = access_route(user_conn, "messages.sessions.get", async |stream| {
        stream.send(&conversation_id).await?;

        let enc_session: EncryptedChatSession = stream.receive::<RouteResult<_>>().await??;

        let sender = user_secret.decrypt(&enc_session.outbound)?;

        Ok(sender.into())
    }).await?;

    let message = access_route(user_conn, "messages.send", async |stream| {
        stream.send(&SendMessageData {
            conversation_id,
            replied_to: None,
            message_body: message_secret.encrypt(&MessageBody {
                content: message.to_string()
            }),
            key_for_author: user_secret.encrypt(&message_secret),
            key_for_others: session.encrypt(message_secret)
        }).await?;

        let msg = stream.receive::<RouteResult<Message>>().await??;

        Ok(msg)
    }).await?;

    Ok(message)
}

async fn process_messages(
    user: &User,
    user_conn: &quinn::Connection
) -> Result<HashMap<SnowflakeID, Secret>> {
    let user_secret = user.secret.unlock(DEFAULT_PASSWORD)?;
    let mut message_secrets = HashMap::new();

    access_route(user_conn, "messages.unread.process", async |stream| {
        let mut unprocessed: HashMap<SnowflakeID, UnprocessedMessage>;

        loop {
            unprocessed = stream.receive::<RouteResult<_>>().await??;

            if unprocessed.is_empty() {
                break;
            }

            let mut processed: HashMap<SnowflakeID, Encrypted<Secret>> = HashMap::new();

            for (message_id, UnprocessedMessage { box_public_key, session_key, message_key }) in unprocessed {
                let session_key = user_secret.unbox_from(&session_key, box_public_key)?;

                let mut inbound = InboundGroupSession::new(
                    &session_key,
                    MegolmSessionConfig::version_1()
                );

                let message_secret = {
                    let dec = inbound.decrypt(&message_key)?;

                    Secret::try_from_bytes(&dec.plaintext)
                        .context("invalid megolm message bytes: was not secret")?
                };

                processed.insert(message_id, user_secret.encrypt(&message_secret));

                message_secrets.insert(message_id, message_secret);
            }

            stream.send(&processed).await?;
        }

        Ok(())
    }).await?;

    Ok(message_secrets)
}

async fn fetch_message_history(
    user: &User,
    user_conn: &quinn::Connection,
    conversation_id: SnowflakeID,
    params: MessageHistoryParams
) -> Result<Vec<(Message, Secret)>> {
    let user_secret = user.secret.unlock(DEFAULT_PASSWORD)?;

    access_route(user_conn, "messages.history.get", async |stream| {
        stream.send(&GetMessageHistoryData {
            conversation_id,
            params,
            limit: 100
        }).await?;

        let data: Vec<(Message, Encrypted<Secret>)> = stream.receive::<RouteResult<Compressed<_>>>().await??.decompress();

        let mut messages = vec![];

        for (msg, enc) in data {
            let secret = user_secret.decrypt(&enc)?;

            messages.push((msg, secret));
        }

        Ok(messages)
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
        SERVER_ADDR,
        cert.clone(),
        key.into(),
        10,
        Arc::new(EchoRouter::new()),
        pool
    ));

    let (alice, alice_conn) = connect_and_create_account("alice", cert.clone()).await?;
    let (bob, bob_conn) = connect_and_create_account("bob", cert.clone()).await?;

    let alice_bob_conv_id = establish_friendship(
        (&alice_conn, &alice),
        (&bob_conn, &bob)
    ).await?;

    access_route(&alice_conn, "users.friends.remove", async |stream| {
        stream.send(&bob.id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    access_route(&bob_conn, "users.friends.get", async |stream| {
        let friends: Vec<Friend> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            friends.is_empty(),
            "bob still had friends after alice removed him"
        );

        Ok(())
    }).await?;

    access_route(&alice_conn, "users.friends.requests.create", async |stream| {
        stream.send(&bob.id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    access_route(&bob_conn, "users.friends.requests.get", async |stream| {
        let requests: Vec<FriendRequest> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            requests.iter().any(|f| f.sender == alice.id),
            "bob did not get a request from alice"
        );

        Ok(())
    }).await?;

    access_route(&bob_conn, "users.friends.requests.decline", async |stream| {
        stream.send(&alice.id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    });

    access_route(&bob_conn, "users.friends.requests.get", async |stream| {
        let requests: Vec<FriendRequest> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            !requests.iter().any(|f| f.sender == alice.id),
            "bob was not able to cancel alice's request"
        );

        Ok(())
    }).await?;

    println!("assertions passed!");

    Ok(())
}
