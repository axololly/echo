use std::{net::{SocketAddr, ToSocketAddrs}, str::FromStr, sync::{Arc, atomic::{AtomicU16, Ordering}}};

use echo_server::{error::RouteError, events::Event, router::EchoRouter, routes::{BanMemberData, CreateFriendRequestData, CreateNewGroupData, CreateNewUserData, FriendRequestKeys, FriendRequestSessionData, GroupAppearanceUpdateData, GroupRouteError, KickMemberData, UnbanMemberData}, runner::run, stream::Stream};
use echo_types::{BannedMember, Group, PasswordProtected, Secret, User, UserSettings, UserState};
use pgtemp::PgTempDB;
use quinn::{crypto::rustls::QuicClientConfig, rustls};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
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
    let olm_account = Account::new();

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
            olm_account: secret.encrypt(&olm_account.pickle()),
            olm_public_key: olm_account.curve25519_key()
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

/// Form a friend request between two users
async fn establish_friendship(
    user1_data: (&quinn::Connection, &User),
    user2_data: (&quinn::Connection, &User)
) -> Result<()> {
    let (conn1, user1) = user1_data;
    let (conn2, user2) = user2_data;

    access_route(conn1, "users.friends.requests.create", async |stream| {
        let secret = user1.secret.unlock(DEFAULT_PASSWORD)?;
        let mut olm: Account = secret.decrypt(&user1.olm_account)?.into();

        let result = olm.generate_one_time_keys(1);

        olm.mark_keys_as_published();

        let one_time_key = result.created[0];

        let data = CreateFriendRequestData {
            receiver: user2.id,
            one_time_key,
            new_account: secret.encrypt(&olm.pickle())
        };

        stream.send(&data).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    access_route(conn2, "users.friends.requests.accept", async |stream| {
        let secret = user2.secret.unlock(DEFAULT_PASSWORD)?;
        let olm: Account = secret.decrypt(&user2.olm_account)?.into();

        stream.send(&user1.id).await?;

        let FriendRequestKeys {
            public_key,
            one_time_key
        } = stream.receive::<RouteResult<_>>().await??;

        let mut session = olm.create_outbound_session(
            SessionConfig::version_1(),
            public_key,
            one_time_key
        )?;

        let OlmMessage::PreKey(pre_key_message) = session.encrypt([])? else {
            unreachable!()
        };

        let data = FriendRequestSessionData {
            session: secret.encrypt(&session.pickle()),
            pre_key_message
        };

        stream.send(&data).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(session)
    }).await?;

    Ok(())
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

    // Alice and Bob create their accounts
    let (alice, alice_conn) = connect_and_create_account("alice", cert.clone()).await?;
    let (bob, bob_conn) = connect_and_create_account("bob", cert.clone()).await?;

    // Alice and Bob become friends
    establish_friendship(
        (&alice_conn, &alice),
        (&bob_conn, &bob)
    ).await?;

    // Chloe joins the service
    let (chloe, chloe_conn) = connect_and_create_account("chloe", cert.clone()).await?;

    // Alice creates a group with Bob in it
    let alice_group = access_route(&alice_conn, "groups.create", async |stream| {
        let data = CreateNewGroupData {
            name: Some("alice's group chat".to_string()),
            initial_members: vec![bob.id]
        };

        stream.send(&data).await?;

        let group: Group = stream.receive::<RouteResult<_>>().await??;

        Ok(group)
    }).await?;

    // Chloe now joins Alice's group
    let chloe_joins_group = async || -> Result<Group> {
        access_route(&chloe_conn, "groups.join", async |stream| {
            stream.send(&alice_group.invite_code).await?;

            let group: Group = stream.receive::<RouteResult<_>>().await??;

            Ok(group)
        }).await
    };

    chloe_joins_group().await?;

    // Alice changes the group's name
    access_route(&alice_conn, "groups.appearance.edit", async |stream| {
        stream.send(&GroupAppearanceUpdateData {
            group_id: alice_group.id,
            new_name: Some("the squad".to_string()),
            new_avatar: None
        }).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Bob gets the new group state to see if
    // Chloe was correctly added and if Alice
    // changed the group name successfully.
    let bob_group = access_route(&bob_conn, "groups.get", async |stream| {
        stream.send(&alice_group.id).await?;

        let group: Group = stream.receive::<RouteResult<_>>().await??;

        assert!(
            group.members.iter().find(|m| m.user_id == chloe.id).is_some(),
            "chloe was not added as a member to the group"
        );

        assert_eq!(
            group.name, "the squad",
            "the group chat did not have its name changed"
        );

        Ok(group)
    }).await?;

    // Bob decides to leave the shared group
    access_route(&bob_conn, "groups.leave", async |stream| {
        stream.send(&bob_group.id).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Alice decides to kick Chloe
    access_route(&alice_conn, "groups.members.kick", async |stream| {
        stream.send(&KickMemberData {
            group_id: alice_group.id,
            member_id: chloe.id
        }).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Check that Chloe can still join back
    chloe_joins_group().await?;

    let ban_reason = "for testing purposes";

    // Alice decides to ban Chloe
    access_route(&alice_conn, "groups.members.ban", async |stream| {
        stream.send(&BanMemberData {
            group_id: alice_group.id,
            member_id: chloe.id,
            reason: Some(ban_reason.to_string())
        }).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Check that Chloe cannot join back because she is banned
    match chloe_joins_group().await {
        Ok(_) => panic!("chloe could still join the group, even when she was banned"),
        Err(report) => {
            let err = report
                .downcast_report::<RouteError>()?
                .into_current_context();

            let RouteError::Group(GroupRouteError::MemberIsBanned { reason, ..  }) = err else {
                unreachable!("another error type was found: {err:?}");
            };

            assert_eq!(reason.as_deref(), Some(ban_reason));
        }
    }

    // Alice checks the ban list to ensure Chloe is in it
    access_route(&alice_conn, "groups.members.banned.get", async |stream| {
        stream.send(&alice_group.id).await?;

        let ban_list: Vec<BannedMember> = stream.receive::<RouteResult<_>>().await??;

        assert!(
            ban_list.iter().find(|m| m.member_id == chloe.id).is_some(),
            "chloe was not found on the ban list"
        );

        Ok(())
    }).await?;

    // Alice unbans Chloe
    access_route(&alice_conn, "groups.members.unban", async |stream| {
        stream.send(&UnbanMemberData {
            group_id: alice_group.id,
            member_id: chloe.id
        }).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(())
    }).await?;

    // Chloe can now join the group
    chloe_joins_group().await?;

    println!("assertions passed!");

    Ok(())
}
