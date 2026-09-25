mod varint;
use varint::{AsyncVarintReader, AsyncVarintWriter};

use std::{fmt::Debug, net::{SocketAddr, ToSocketAddrs}, sync::Arc, time::Duration};

use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt, crypto::rustls::{QuicClientConfig, QuicServerConfig}, rustls::{ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject}}};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rootcause::{Result, bail, option_ext::OptionExt, prelude::ResultExt};
use serde::{Serialize, de::DeserializeOwned};

fn into_socket_addrs(addr: impl ToSocketAddrs + Debug) -> Result<SocketAddr, &'static str> {
    addr.to_socket_addrs()
        .context("failed to resolve IP")?
        .next()
        .context("failed to resolve IP - none found")
}

async fn connect_to_server(
    client_addr: impl ToSocketAddrs + Debug,
    server_addr: impl ToSocketAddrs + Debug,
    cert: CertificateDer<'_>
) -> Result<Connection> {
    let mut root_store = RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );

    root_store.add(cert)?;

    if root_store.is_empty() {
        bail!("no TLS server certificates");
    }

    let mut client_crypto = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let client_config = ClientConfig::new(
        Arc::new(
            QuicClientConfig::try_from(client_crypto)?
        )
    );

    let mut endpoint = Endpoint::client(into_socket_addrs(client_addr)?)?;

    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(into_socket_addrs(server_addr)?, "localhost")?
        .await?;

    Ok(connection)
}

async fn run_server(
    server_addr: impl ToSocketAddrs + Debug,
    max_connections: usize,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>
) -> Result<()> {
    let mut crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    // Telling the peer's TLS client this TLS client only supports QUIC.
    crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    // Conver the TLS options into QUIC options
    let mut config = ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(crypto).unwrap())
    );

    let transport = Arc::get_mut(&mut config.transport).unwrap();

    // Wait a max of 30s before declaring the connection as dead
    transport.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    // Send keep-alive packets every 10s to prevent the connection from closing
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    // Finally, construct the endpoint that the server uses
    // to accept incoming connections
    let endpoint = Endpoint::server(config, into_socket_addrs(server_addr)?)?;

    while let Some(inc) = endpoint.accept().await {
        if endpoint.open_connections() >= max_connections {
            inc.refuse();
            continue;
        }

        // TODO: check for blacklisted IPs here and refuse any that are

        if !inc.remote_address_validated() {
            inc.retry()?;
            continue;
        }

        let conn = inc.await?;

        tokio::spawn(handle_streams(conn));
    }

    Ok(())
}

struct Stream {
    sender: SendStream,
    receiver: RecvStream
}

impl Stream {
    pub fn new(sender: SendStream, receiver: RecvStream) -> Self {
        Self { sender, receiver }
    }

    pub async fn send<T: Serialize>(&mut self, data: &T) -> Result<()> {
        let bytes = bitcode::serialize(data)?;

        self.sender.write_varint(bytes.len() as u64).await?;

        self.sender.write_all(&bytes).await?;

        Ok(())
    }

    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let len: u64 = self.receiver.read_varint().await?;

        let buf = &mut vec![0u8; len as usize];

        self.receiver.read_exact(buf).await?;

        let obj = bitcode::deserialize(buf)?;

        Ok(obj)
    }

    pub fn close(mut self) -> Result<()> {
        self.sender.finish()?;
        self.receiver.stop(0_u32.into())?;

        Ok(())
    }
}

async fn handle_streams(conn: Connection) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(e) => {
                println!("Error handling streams on server: {e:?}");
                continue;
            }
        };

        let stream = Stream::new(send, recv);

        tokio::spawn(async {
            if let Err(e) = handle_single_stream(stream).await {
                println!("Error with stream on server: {e:?}")
            }
        });
    }
}

async fn handle_single_stream(mut stream: Stream) -> Result<()> {
    let data: String = stream.receive().await?;

    if data == "echo" {
        stream.send(&data).await?;
    }

    stream.close()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
        "localhost".to_string()
    ])?;

    let server_cert = CertificateDer::from(cert.der().to_vec());

    let server_key = PrivateKeyDer::from_pem_slice(
        signing_key.serialize_pem().as_bytes()
    )?;

    let client_addr = "localhost:6453";
    let server_addr = "localhost:4433";

    tokio::spawn(run_server(
        server_addr,
        10,
        server_cert.clone(),
        server_key
    ));

    let conn = connect_to_server(
        client_addr,
        server_addr,
        server_cert
    ).await?;

    let (send, recv) = conn.open_bi().await?;
    let mut stream = Stream::new(send, recv);

    stream.send(&"echo").await?;

    let response: String = stream.receive().await?;

    println!("response from server: {response:?}");

    Ok(())
}
