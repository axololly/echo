use std::{net::ToSocketAddrs, sync::Arc, time::Duration};

use rootcause::{Result, compat::boxed_error::IntoBoxedError, option_ext::OptionExt};
use sqlx::postgres::PgPool;

use quinn::{Endpoint, ServerConfig, VarInt, crypto::rustls::QuicServerConfig, rustls::{ServerConfig as RustlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}};

use crate::{connection::Connection, router::{EchoContext, EchoRouter}};

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
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    max_connections: usize,
    router: Arc<EchoRouter>,
    pool: PgPool
) -> Result<()> {
    let mut crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

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

    while let Some(inc) = endpoint.accept().await {
        if endpoint.open_connections() >= max_connections {
            inc.refuse();
            continue;
        }

        // TODO: check for blacklisted IPs here and refuse any that are

        // Ensure the client validates their IP address.
        if !inc.remote_address_validated() {
            inc.retry()?;
            continue;
        }

        let conn = inc.await?;

        // Move handling incoming requests out of this thread.
        tokio::spawn(handle_incoming_requests(conn, router.clone(), pool.clone()));
    }

    Ok(())
}

/// Handle incoming QUIC streams from the parent QUIC [`Connection`],
/// and then redirecting them through the router.
///
/// [`Connection`]: quinn::Connection
async fn handle_incoming_requests(
    parent: quinn::Connection,
    router: Arc<EchoRouter>,
    pool: PgPool
) -> Result<()> {
    loop {
        let mut conn = Connection::accept_bi(&parent).await?;

        let route_name: String = conn.receive().await?;

        let mut ctx = EchoContext {
            route_name,
            conn,
            pool: pool.clone()
        };

        let result = router.run_with(&mut ctx).await;

        if let Err(report) = &result {
            println!("Error encountered on server: {report:?}");
        }

        let stripped = result.map_err(|report| report.into_current_context());

        ctx.conn.send(&stripped).await?;
    }
}
