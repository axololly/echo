use std::{net::ToSocketAddrs, sync::Arc};

use rootcause::{Result, option_ext::OptionExt};
use sqlx::postgres::PgPool;

use quinn::{VarInt, crypto::rustls::QuicServerConfig, rustls::{self, pki_types::{CertificateDer, PrivateKeyDer}}};

use crate::{connection::Connection, router::{EchoContext, EchoRouter}};

pub async fn run(
    local_addr: impl ToSocketAddrs,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    max_connections: usize,
    router: Arc<EchoRouter>,
    pool: PgPool
) -> Result<()> {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut config = quinn::ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(crypto).unwrap())
    );

    let transport = Arc::get_mut(&mut config.transport).unwrap();

    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    let local_addr = local_addr
        .to_socket_addrs()?
        .next()
        .context("could not resolve local address")?;

    let endpoint = quinn::Endpoint::server(config, local_addr)?;

    while let Some(inc) = endpoint.accept().await {
        if endpoint.open_connections() >= max_connections {
            inc.refuse();
            continue;
        }

        // TODO: check for blacklisted IPs here and refuse any that are

        if inc.remote_address_validated() {
            inc.retry()?;
            continue;
        }

        let conn = inc.await?;

        tokio::spawn(handle_incoming_requests(conn, router.clone(), pool.clone()));
    }

    Ok(())
}

async fn handle_incoming_requests(
    parent: quinn::Connection,
    router: Arc<EchoRouter>,
    pool: PgPool
) -> Result<()> {
    loop {
        let mut conn = Connection::accept_bi(&parent).await?;

        let resource: String = conn.receive().await?;

        let ctx = EchoContext {
            resource,
            conn,
            pool: pool.clone(),
            user: None
        };

        router.run_with(ctx).await?;
    }
}
