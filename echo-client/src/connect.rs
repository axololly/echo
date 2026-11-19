use std::{net::SocketAddr, sync::Arc};

use echo_server::{error::RouteError, stream::Stream};
use quinn::{Connection as QuicConnection, crypto::rustls::QuicClientConfig, rustls};
use rootcause::{Result, prelude::ResultExt, report};
use tokio::{io, net::{ToSocketAddrs, lookup_host}};

pub(crate) type RouteResult<T> = std::result::Result<T, RouteError>;

/// Resolve an address using DNS
pub async fn resolve_socket_addr(addr: impl ToSocketAddrs) -> Result<Vec<SocketAddr>, io::Error> {
    let iter = lookup_host(addr).await?;

    Ok(iter.collect())
}

#[derive(Clone)]
#[repr(transparent)]
pub struct ServerConnection(QuicConnection);

impl ServerConnection {
    /// Access a route on the server and interact with the resulting stream.
    /// The stream will be automatically closed.
    pub(crate) async fn access_route<R>(
        &self,
        route: &str,
        stream_fn: impl AsyncFnOnce(&mut Stream) -> Result<R>
    ) -> Result<R> {
        let mut stream = Stream::open_bi(&self.0).await?;

        stream.send(&route).await?;

        stream.receive::<RouteResult<()>>().await??;

        let out = stream_fn(&mut stream).await?;

        stream.close()?;

        Ok(out)
    }

    /// Access a route on the server, handing over the resulting stream to the caller.
    pub(crate) async fn access_route_manually(&self, route: &str) -> Result<Stream> {
        let mut stream = Stream::open_bi(&self.0).await?;

        stream.send(&route).await?;

        stream.receive::<RouteResult<()>>().await??;

        Ok(stream)
    }
}

/// Try to establish a QUIC connection with a given server address.
///
/// This will use the domain name as the server name.
pub async fn connect_to_server(host: &str, port: u16) -> Result<ServerConnection> {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = quinn::ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .context("failed to convert rustls client config to QUIC client config")?
        )
    );

    let mut endpoint = quinn::Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;

    endpoint.set_default_client_config(client_config);

    let server_addrs = resolve_socket_addr((host, port)).await?;

    let mut conn = None;
    let mut connection_errors = report!("failed to connect to server");

    for addr in server_addrs {
        match endpoint.connect(addr, host) {
            Ok(fut) => match fut.await {
                Ok(c) => {
                    conn = Some(c);
                },
                Err(e) => {
                    connection_errors = connection_errors.attach(
                        format!("failed to connect to {addr:?}: {e:?}")
                    );
                }
            },
            Err(e) => {
                connection_errors = connection_errors.attach(
                    format!("failed to initialise connection to {addr:?}: {e:?}")
                );
            }
        }
    }

    conn.map(ServerConnection)
        .ok_or(connection_errors)
}
