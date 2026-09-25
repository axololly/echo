use std::{fmt::Debug, net::ToSocketAddrs, sync::Arc};

use async_trait::async_trait;
use quinn::{Connection, Endpoint, ServerConfig, VarInt, crypto::rustls::QuicServerConfig, rustls::{ServerConfig as RustlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer}}};
use rootcause::Result;

use crate::{into_socket_addrs, router::{Route, Router}, stream::Stream};

pub async fn run_server(
    server_addr: impl ToSocketAddrs + Debug,
    max_connections: usize,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    router: Arc<Router>
) -> Result<()> {
    let mut crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut config = ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(crypto).unwrap())
    );

    let transport = Arc::get_mut(&mut config.transport).unwrap();

    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    let endpoint = Endpoint::server(config, into_socket_addrs(server_addr)?)?;

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

        tokio::spawn(handle_streams(conn, router.clone()));
    }

    Ok(())
}

async fn handle_streams(conn: Connection, router: Arc<Router>) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(e) => {
                println!("Error handling streams on server: {e:?}");
                continue;
            }
        };

        println!("accepted stream on server");

        let mut stream = Stream::new(send, recv);

        let resource: String = match stream.receive().await {
            Ok(data) => data,
            Err(e) => {
                println!("Error handling streams on server: {e:?}");
                continue;
            }
        };

        println!("getting route for resource {resource:?}");

        let Some(route) = router.get_route(&resource) else {
            let _ = stream.close();

            continue;
        };

        println!("found it! running callback");

        if let Err(e) = route.callback(stream).await {
            println!("Error in the callback for route {resource:?}:\n{e:?}");
        }
    }
}

pub struct EchoRoute;

#[async_trait]
impl Route for EchoRoute {
    fn name(&self) ->  &'static str {
        "echo"
    }

    async fn callback(&self, mut stream: Stream) -> Result<()> {
        stream.send(&"echo").await?;

        stream.close()?;

        Ok(())
    }
}
