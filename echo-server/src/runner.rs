use std::{net::ToSocketAddrs, path::Path, sync::{Arc, LazyLock}, time::Duration};

use dashmap::DashMap;
use echo_types::SnowflakeID;
use rootcause::{Result, option_ext::OptionExt, prelude::ResultExt};
use sqlx::postgres::PgPool;
use quinn::{Endpoint, ServerConfig, VarInt, crypto::rustls::QuicServerConfig, rustls::{ServerConfig as RustlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}};
use tokio::sync::Mutex;

use crate::{asset_storage::AssetStorage, backoffice::{RunningTasks, TaskContext, run_all_tasks}, error::ANOTHER_DEVICE_LOGGED_IN, events::{EventDispatcher, ProfileUpdatePubSub, TypingEventPubSub}, execute, router::{EchoContext, EchoRouter}, stream::Stream};

/// Run the Echo server.
///
/// This will open a QUIC endpoint on the given `server_addr`
/// using the certificate and key supplied for handshakes.
///
/// The router and pool will be cloned for connections to
/// accept API requests over QUIC streams.
///
/// `max_connections` determines how many QUIC connections
/// to accept at one given time.
pub async fn run(
    server_addr: impl ToSocketAddrs,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    max_connections: usize,
    router: Arc<EchoRouter>,
    pool: PgPool,
    asset_dir: impl AsRef<Path>
) -> Result<()> {
    let mut crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut config = ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(crypto).unwrap())
    );

    let transport = Arc::get_mut(&mut config.transport).unwrap();

    // If no data is received for 30 seconds, the connection is dropped.
    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    // Send keep-alive packets every 10 seconds to keep the connection alive.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    let local_addr = server_addr
        .to_socket_addrs()?
        .next()
        .context("could not resolve local address")?;

    let endpoint = Endpoint::server(config, local_addr)?;

    let event_dispatcher = EventDispatcher::default();

    let typing_event_pubsub = TypingEventPubSub::with_dispatcher(event_dispatcher.clone());
    let profile_update_pubsub = ProfileUpdatePubSub::with_dispatcher(event_dispatcher.clone());

    let asset_storage = AssetStorage::new(
        asset_dir.as_ref().to_path_buf()
    );

    let running_tasks = run_all_tasks(TaskContext {
        pool: pool.clone()
    });

    while let Some(inc) = endpoint.accept().await {
        if endpoint.open_connections() >= max_connections {
            inc.refuse();
            continue;
        }

        // Ensure the client validates their IP address.
        if !inc.remote_address_validated() {
            inc.retry()?;
            continue;
        }

        let conn = inc.await?;

        // Move handling incoming requests out of this thread.
        tokio::spawn(handle_incoming_requests(
            conn,
            router.clone(),
            pool.clone(),
            event_dispatcher.clone(),
            asset_storage.clone(),
            running_tasks.clone(),
            (
                typing_event_pubsub.clone(),
                profile_update_pubsub.clone()
            )
        ));
    }

    Ok(())
}

static USER_CONNECTIONS: LazyLock<DashMap<SnowflakeID, quinn::Connection>> = LazyLock::new(DashMap::new);

/// Handle incoming QUIC streams from the parent QUIC [`Connection`],
/// and then redirecting them through the router.
///
/// [`Connection`]: quinn::Connection
async fn handle_incoming_requests(
    parent: quinn::Connection,
    router: Arc<EchoRouter>,
    pool: PgPool,
    dispatcher: EventDispatcher,
    asset_storage: AssetStorage,
    running_tasks: RunningTasks,
    pubsubs: (TypingEventPubSub, ProfileUpdatePubSub)
) -> Result<()> {
    let client_ip = parent.remote_address();
    let authenticated_user: Arc<Mutex<Option<SnowflakeID>>> = Arc::new(Mutex::new(None));
    let (typing_event_pubsub, profile_update_pubsub) = pubsubs;

    tokio::spawn(handle_disconnect(
        parent.clone(),
        pool.clone(),
        typing_event_pubsub.clone(),
        profile_update_pubsub.clone(),
        authenticated_user.clone()
    ));

    while let Ok(mut stream) = Stream::accept_bi(&parent).await {
        let user_before_request = *authenticated_user.lock().await;

        let route_name: String = stream.receive().await?;

        let ctx = EchoContext {
            route_name,
            stream,
            dispatcher: dispatcher.clone(),
            asset_storage: asset_storage.clone(),
            running_tasks: running_tasks.clone(),
            pool: pool.clone(),
            user: { *authenticated_user.lock().await },
            typing_event_pubsub: typing_event_pubsub.clone(),
            profile_update_pubsub: profile_update_pubsub.clone()
        };

        // Make a new task for each request that gets handled.
        // This is to allow multiple requests to be handled at the same time.
        tokio::spawn(handle_single_request(
            ctx,
            router.clone(),
            authenticated_user.clone()
        ));

        let user_after_request = *authenticated_user.lock().await;

        if user_before_request != user_after_request
            && let Some(user_id) = user_after_request
        {
            let prev_conn = USER_CONNECTIONS.insert(user_id, parent.clone());

            if let Some(conn) = prev_conn {
                conn.close(
                    ANOTHER_DEVICE_LOGGED_IN,
                    format!("Another device logged in to this account under the IP {client_ip}").as_bytes()
                );
            }
        }
    }

    Ok(())
}

async fn handle_single_request(
    mut ctx: EchoContext,
    router: Arc<EchoRouter>,
    authenticated_user: Arc<Mutex<Option<SnowflakeID>>>
) -> Result<()> {
    router.run_with(&mut ctx).await?;

    let mut auth_user = authenticated_user.lock().await;

    if ctx.user != *auth_user && let Some(user_id) = ctx.user {
        let mut tx = ctx.pool.begin().await?;

        execute!(
            &mut *tx,
            "UPDATE users SET status = 'Online' WHERE id = $1",
            user_id
        );

        ctx.profile_update_pubsub.publish(user_id);

        if let Some(prev) = *auth_user {
            execute!(
                &mut *tx,
                "UPDATE users SET status = 'Offline' WHERE id = $1",
                prev
            );

            ctx.profile_update_pubsub.publish(prev);
        }

        tx.commit().await?;

        *auth_user = ctx.user;
    }

    Ok(())
}

async fn handle_disconnect(
    conn: quinn::Connection,
    pool: PgPool,
    typing_event_pubsub: TypingEventPubSub,
    profile_update_pubsub: ProfileUpdatePubSub,
    authenticated_user: Arc<Mutex<Option<SnowflakeID>>>
) -> Result<()> {
    conn.closed().await;

    let Some(user_id) = *authenticated_user.lock().await else {
        return Ok(());
    };

    typing_event_pubsub.unsubscribe(user_id);
    profile_update_pubsub.unsubscribe_all(user_id);

    USER_CONNECTIONS.remove(&user_id);

    execute!(
        &pool,
        "UPDATE users SET status = 'Offline' WHERE id = $1",
        user_id
    );

    Ok(())
}
